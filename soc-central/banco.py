import datetime
from sqlalchemy import create_engine, text, Column, Integer, String, Boolean, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
import config

# 1. Criação do Banco de Dados caso não exista
try:
    # Conecta-se ao servidor MySQL sem especificar banco de dados inicialmente
    temp_engine = create_engine(config.MYSQL_ENGINE_URL)
    with temp_engine.connect() as conn:
        conn.execute(text(f"CREATE DATABASE IF NOT EXISTS {config.MYSQL_DATABASE} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"))
        conn.execute(text("COMMIT"))
    temp_engine.dispose()
except Exception as e:
    print(f"⚠️ Erro/Alerta ao tentar criar banco {config.MYSQL_DATABASE}: {e}")

# 2. Configurações de Engine e Session do SQLAlchemy
engine = create_engine(config.DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- MODELOS DAS TABELAS ---

class Cliente(Base):
    __tablename__ = 'clientes'
    
    id = Column(Integer, primary_key=True, index=True)
    nome = Column(String(255), nullable=False)
    token = Column(String(255), unique=True, index=True, nullable=False)
    criado_em = Column(DateTime, default=datetime.datetime.utcnow)
    ativo = Column(Boolean, default=True)

class Evento(Base):
    __tablename__ = 'eventos'
    
    id = Column(Integer, primary_key=True, index=True)
    cliente_id = Column(Integer, ForeignKey('clientes.id', ondelete='CASCADE'), nullable=False)
    hora = Column(String(50), nullable=False)
    alertas = Column(JSON, nullable=False)  # Lista de alertas estruturados/mensagens
    risco = Column(String(50), nullable=False)
    analise = Column(Text, nullable=True)
    acoes = Column(JSON, nullable=False)    # Lista de ações tomadas
    
    cliente = relationship("Cliente")

class PadraoCliente(Base):
    __tablename__ = 'padroes_cliente'
    
    id = Column(Integer, primary_key=True, index=True)
    cliente_id = Column(Integer, ForeignKey('clientes.id', ondelete='CASCADE'), nullable=False)
    chave = Column(String(255), nullable=False)     # Ex: cpu_avg, ram_avg, conexoes_avg
    valor = Column(String(255), nullable=False)     # Valor armazenado (média calculada)
    atualizado_em = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    
    cliente = relationship("Cliente")

class IPMalicioso(Base):
    __tablename__ = 'ips_maliciosos'
    
    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String(50), unique=True, index=True, nullable=False)
    total_deteccoes = Column(Integer, default=1)
    clientes_afetados = Column(JSON, nullable=False)  # Lista de IDs de clientes afetados
    primeiro_visto = Column(DateTime, default=datetime.datetime.utcnow)
    ultimo_visto = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)


def inicializar_banco():
    """
    Cria as tabelas automaticamente no banco de dados se não existirem.
    """
    Base.metadata.create_all(bind=engine)
    print("✅ Tabelas do banco soc_central inicializadas com sucesso.")
