"""notificacao agrupada por ator

Revision ID: 0016
Revises: 0015
Create Date: 2026-09-09

Etapa 3 do rastreamento de ator, e a razao pela qual o notificador foi escrito
com a chave de agrupamento numa funcao sozinha.

O problema: hoje a fila agrupa por regra mais IP. Um atacante que roda de cinco
enderecos gera cinco mensagens identicas, uma por IP, e quem recebe conclui que
sao cinco incidentes. Trocar de IP e barato, e o notificador estava pagando
esse preco.

Com esta coluna, quando o IP de origem pertence a um ator conhecido, a chave
passa a ser regra mais ator. Os cinco IPs viram UMA mensagem que diz de quantos
enderecos aquilo veio.

O IP continua guardado em source_ip: agrupar por ator nao pode custar a
evidencia de onde a coisa saiu.

Por que a coluna e o ref e nao o actors.id: ref e estavel e legivel, do tipo
que se fala em voz alta numa reuniao, e a mensagem ja entregue continua fazendo
sentido mesmo que a linha do ator seja recriada. Tambem nao ha FK de proposito,
pela mesma razao: apagar um ator nao pode apagar o historico de que a mensagem
foi enviada.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0016"
down_revision: Union[str, None] = "0015"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("alert_notifications", sa.Column("actor_ref", sa.String(12)))

    # Chave geral por canal. Nasce ligada porque agrupar por ator e estritamente
    # melhor que agrupar por IP quando existe ator: no pior caso nao ha ator
    # nenhum e a chave continua sendo regra mais IP, exatamente como antes.
    # Quem quiser uma mensagem por endereco desliga aqui.
    op.add_column(
        "notification_channels",
        sa.Column("group_by_actor", sa.Boolean, nullable=False, server_default=sa.true()),
    )

    # Etapa 2: separar um IP do ator na mao deixa um tumulo, nao um buraco.
    #
    # A linha continua em actor_ips com manual ligado e sem dono. E ela que
    # impede o laco de refazer no ciclo seguinte a juncao que a pessoa acabou
    # de desfazer, que e a mesma regra do desfazer da prevencao: automacao nao
    # reverte decisao humana. Apagar a linha faria o IP voltar sozinho.
    op.alter_column("actor_ips", "actor_id", existing_type=sa.BigInteger(), nullable=True)


def downgrade() -> None:
    # Vinculo orfao nao cabe na versao anterior, onde a coluna e obrigatoria.
    op.execute("DELETE FROM actor_ips WHERE actor_id IS NULL")
    op.alter_column("actor_ips", "actor_id", existing_type=sa.BigInteger(), nullable=False)
    op.drop_column("notification_channels", "group_by_actor")
    op.drop_column("alert_notifications", "actor_ref")
