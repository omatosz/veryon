"""retencao e compressao: o banco para de crescer sozinho

Revision ID: 0014
Revises: 0013
Create Date: 2026-09-09

Sem isto, raw_events, alerts e api_requests crescem para sempre. Em producao o
disco enche, o Postgres para de aceitar escrita e o SOC inteiro cai junto,
sempre de madrugada e sempre sem aviso.

Esta migration liga a maquinaria no banco. Os prazos de cada politica ficam no
.env e sao aplicados por app/core/retention.py toda vez que o backend sobe, o
que evita ter que escrever migration nova para trocar "90 dias" por "30 dias".

Tres coisas acontecem aqui:

1. Compressao ligada nas tres hypertables. Medido nos dados reais deste banco,
   com os 11915 registros de api_requests: 5336 kB viraram 256 kB, ou 20 vezes
   menos. O dado continua consultavel, so fica em formato colunar.

2. Chunk skipping na coluna id. O motor de deteccao le raw_events com
   "WHERE id > checkpoint", sem filtro por ts, entao o Postgres nao consegue
   descartar chunk nenhum e olha todos a cada 10 segundos. Enquanto tudo esta
   descomprimido isso e barato. Depois da compressao passaria a descomprimir
   historico inteiro a cada volta. Com o chunk skipping, cada chunk comprimido
   guarda o menor e o maior id que tem dentro, e o planejador descarta de cara
   os que nao podem conter o que se procura. O mesmo vale para o notificador,
   que le alerts do mesmo jeito.

3. Chunk de 1 dia em api_requests, no lugar dos 7 dias padrao.

   O item 3 conserta um bug silencioso que ja existe hoje. A retencao do
   Timescale apaga chunk inteiro, nunca linha solta. Com chunk de 7 dias e
   retencao de 7 dias, um chunk so pode ser apagado quando seu ultimo registro
   passa do prazo, ou seja, o banco guarda entre 7 e 14 dias em vez de 7. Foi
   o que se viu neste banco: a politica de retencao criada na 0008 rodou tres
   vezes com sucesso e mesmo assim havia registro de 12 dias atras. Com chunk
   de 1 dia, a retencao passa a errar por no maximo um dia.

   raw_events e alerts continuam com chunk de 7 dias porque tem volume baixo,
   e chunk pequeno demais so multiplica o custo de planejamento.

Escolha da chave de segmento, uma por tabela. Coluna que vira segmento fica
guardada sem compressao e pode ser filtrada sem descomprimir nada:

  raw_events    source      poucos valores distintos (cowrie, linux, ...)
  alerts        level       cinco valores, e e por onde a tela filtra
  api_requests  client_ip   e a pergunta da investigacao: o que este IP fez

Em api_requests as tres opcoes testadas (client_ip, route, method+status_code)
foram medidas nos dados reais. route ficou em 17.6x e as outras em 20.8x, e
por isso route foi descartada: agrupa demais e cria segmento pequeno.
"""
from typing import Sequence, Union

from alembic import op

revision: str = "0014"
down_revision: Union[str, None] = "0013"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# tabela -> (coluna de segmento, coluna de ordem)
TABELAS = {
    "raw_events": "source",
    "alerts": "level",
    "api_requests": "client_ip",
}


def upgrade() -> None:
    # O chunk skipping e desligado por padrao no Timescale e a chave e por
    # sessao, entao ligar so aqui dentro nao serviria de nada: o motor de
    # deteccao e o notificador abrem conexao propria. Ligando no banco, toda
    # conexao nova ja nasce com ele.
    op.execute(
        """
        DO $$
        BEGIN
            EXECUTE format(
                'ALTER DATABASE %I SET timescaledb.enable_chunk_skipping = on',
                current_database()
            );
        EXCEPTION WHEN OTHERS THEN
            RAISE NOTICE 'sem permissao para ALTER DATABASE, seguindo sem chunk skipping';
        END $$
        """
    )

    op.execute("SELECT set_chunk_time_interval('api_requests', INTERVAL '1 day')")

    for tabela, segmento in TABELAS.items():
        op.execute(
            f"""
            ALTER TABLE {tabela} SET (
                timescaledb.compress,
                timescaledb.compress_segmentby = '{segmento}',
                timescaledb.compress_orderby = 'ts DESC, id DESC'
            )
            """
        )
        # Bloco tolerante: em Postgres sem o agendador do Timescale, ou com a
        # chave acima recusada, a aplicacao ainda tem que subir. Perder o
        # chunk skipping deixa a consulta lenta, nao errada.
        op.execute(
            f"""
            DO $$
            BEGIN
                PERFORM enable_chunk_skipping('{tabela}', 'id');
            EXCEPTION WHEN OTHERS THEN
                RAISE NOTICE 'chunk skipping indisponivel em {tabela}, seguindo sem ele';
            END $$
            """
        )

    # Valores de partida. Quem manda depois do primeiro boot e o .env, lido
    # por app/core/retention.py. Ficam aqui para que um banco recem-criado ja
    # nasca com politica, mesmo que ninguem nunca suba o backend.
    #
    # alerts nao ganha retencao de proposito. Apagar alerta e apagar a memoria
    # do produto, e o padrao de um SOC nao pode ser esquecer. A compressao ja
    # resolve o tamanho. Quem precisar apagar liga ALERTS_DROP_AFTER_DAYS.
    politicas = [
        ("raw_events", "add_compression_policy", "7 days"),
        ("raw_events", "add_retention_policy", "90 days"),
        ("alerts", "add_compression_policy", "30 days"),
        ("api_requests", "add_compression_policy", "2 days"),
        ("api_requests", "add_retention_policy", "7 days"),
    ]
    for tabela, funcao, prazo in politicas:
        # if_not_exists por causa de api_requests, que ja recebeu retencao na
        # 0008. Sem isso a migration quebraria num banco existente.
        op.execute(
            f"""
            DO $$
            BEGIN
                PERFORM {funcao}('{tabela}', INTERVAL '{prazo}', if_not_exists => true);
            EXCEPTION WHEN OTHERS THEN
                RAISE NOTICE 'politica {funcao} indisponivel em {tabela}, seguindo sem ela';
            END $$
            """
        )


def downgrade() -> None:
    for tabela in TABELAS:
        op.execute(
            f"""
            DO $$
            BEGIN
                PERFORM remove_compression_policy('{tabela}', if_exists => true);
                PERFORM remove_retention_policy('{tabela}', if_exists => true);
            EXCEPTION WHEN OTHERS THEN
                RAISE NOTICE 'nada a remover em {tabela}';
            END $$
            """
        )
        # Descomprimir antes de desligar: o Timescale recusa desligar a
        # compressao enquanto existir chunk comprimido, e com razao. O dado
        # dentro dele nao teria para onde voltar.
        op.execute(
            f"""
            DO $$
            DECLARE c regclass;
            BEGIN
                FOR c IN SELECT show_chunks('{tabela}') LOOP
                    PERFORM decompress_chunk(c, if_compressed => true);
                END LOOP;
                PERFORM disable_chunk_skipping('{tabela}', 'id', if_not_exists => true);
            EXCEPTION WHEN OTHERS THEN
                RAISE NOTICE 'falha ao reverter compressao em {tabela}';
            END $$
            """
        )
        op.execute(f"ALTER TABLE {tabela} SET (timescaledb.compress = false)")

    op.execute("SELECT set_chunk_time_interval('api_requests', INTERVAL '7 days')")

    # A retencao de api_requests existia antes desta migration, na 0008.
    # Reverter para a 0013 tem que devolver o banco ao estado dela.
    op.execute(
        """
        DO $$
        BEGIN
            PERFORM add_retention_policy('api_requests', INTERVAL '7 days', if_not_exists => true);
        EXCEPTION WHEN OTHERS THEN
            RAISE NOTICE 'retencao automatica indisponivel, seguindo sem ela';
        END $$
        """
    )
