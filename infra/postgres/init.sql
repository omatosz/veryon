-- Habilita a extensão TimescaleDB no banco principal.
-- Tabelas de série temporal (eventos, alertas) serão convertidas
-- em hypertables nas fases seguintes, quando o schema for definido.
CREATE EXTENSION IF NOT EXISTS timescaledb;
