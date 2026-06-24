from pydantic import BaseModel
from typing import List, Dict

class RegistrarClienteEntrada(BaseModel):
    nome: str

from typing import Union

class EventoEntrada(BaseModel):
    alertas: list[Union[dict, str]]
    metricas: dict
    hora: str
    os: str

class RespostaAnalise(BaseModel):
    risco: str       # BAIXO, MÉDIO, ALTO, CRÍTICO
    analise: str
    acoes: List[str]
    ameacas_coletivas: List[dict]
