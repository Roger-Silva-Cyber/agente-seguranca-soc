import os
import secrets
from pathlib import Path
from dotenv import load_dotenv
from fastapi import Depends, HTTPException, Security, Header, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from banco import SessionLocal, Cliente

# Carrega .env
load_dotenv(Path(__file__).parent / ".env")

# Define uma única vez
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "").replace('"', '').strip()
print(f"AUTH.PY ADMIN_TOKEN CARREGADO: {'OK' if ADMIN_TOKEN else 'AUSENTE ⚠️'}")

security = HTTPBearer()

def obter_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def gerar_token_cliente():
    return secrets.token_urlsafe(32)

def validar_token_cliente(credentials: HTTPAuthorizationCredentials = Security(security), db: Session = Depends(obter_db)):
    token = credentials.credentials
    cliente = db.query(Cliente).filter(Cliente.token == token, Cliente.ativo == True).first()
    if not cliente:
        raise HTTPException(status_code=401, detail="Token inválido")
    return cliente

def validar_admin_token(authorization: str = Header(...)):
    token = authorization.replace("Bearer ", "").strip()
    if token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Acesso administrativo não autorizado")
    return token