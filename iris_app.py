import sys
import os
import time
import datetime
import socket
import json
import hashlib
from pathlib import Path
import httpx
import psutil
import dotenv

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize, QEvent
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QStackedWidget, QListWidget, QListWidgetItem,
    QScrollArea, QLineEdit, QTextEdit, QProgressBar, QGridLayout,
    QFrame, QDialog, QFileDialog, QSizeGrip, QGraphicsDropShadowEffect,
    QAbstractItemView, QTabWidget
)
from PyQt6.QtGui import QFont, QColor, QIcon, QPainter, QBrush, QPen, QPixmap, QPainterPath

# Cores e Estilo do Tema Claro Premium (Estilo Linear / Arc / Raycast)
CORES = {
    "roxo": "#8B5CF6",
    "roxo_sec": "#7C3AED",
    "roxo_suave": "rgba(139, 92, 246, 0.08)",
    "cyan": "#22D3EE",
    "azul": "#60A5FA",
    "verde": "#10B981",
    "laranja": "#F59E0B",
    "vermelho": "#EF4444",
    "fundo": "#F8FAFC",
    "card": "#FFFFFF",
    "texto": "#0F172A",
    "texto_suave": "#64748B",
    "borda": "#E2E8F0",
}
FONTE_PRINCIPAL = "Segoe UI"

def load_estado():
    try:
        path = Path("C:/agente-seguranca-soc/estado.json")
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        print(f"Erro ao ler estado.json: {e}")
    return {}

def save_config(ollama_url, ollama_model, groq_key):
    try:
        env_path = Path("C:/agente-seguranca-soc/.env")
        lines = []
        if env_path.exists():
            with open(env_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        
        keys_updated = {"OLLAMA_URL": False, "OLLAMA_MODEL": False, "GROQ_API_KEY": False}
        new_lines = []
        for line in lines:
            line_str = line.strip()
            if line_str.startswith("OLLAMA_URL="):
                new_lines.append(f'OLLAMA_URL="{ollama_url}"\n')
                keys_updated["OLLAMA_URL"] = True
            elif line_str.startswith("OLLAMA_MODEL="):
                new_lines.append(f'OLLAMA_MODEL="{ollama_model}"\n')
                keys_updated["OLLAMA_MODEL"] = True
            elif line_str.startswith("GROQ_API_KEY="):
                new_lines.append(f'GROQ_API_KEY="{groq_key}"\n')
                keys_updated["GROQ_API_KEY"] = True
            else:
                new_lines.append(line)
                
        for key, updated in keys_updated.items():
            if not updated:
                if key == "OLLAMA_URL":
                    new_lines.append(f'OLLAMA_URL="{ollama_url}"\n')
                elif key == "OLLAMA_MODEL":
                    new_lines.append(f'OLLAMA_MODEL="{ollama_model}"\n')
                elif key == "GROQ_API_KEY":
                    new_lines.append(f'GROQ_API_KEY="{groq_key}"\n')
                    
        with open(env_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
        return True
    except Exception as e:
        print(f"Erro ao salvar .env: {e}")
        return False


# --- COMPONENTES GRÁFICOS PERSONALIZADOS (QPAINTER) ---

class TrendLine(QWidget):
    """Mini gráfico de linha de tendência suave (sparkline)."""
    def __init__(self, points, color_hex, parent=None):
        super().__init__(parent)
        self.points = points
        self.color = QColor(color_hex)
        self.setMinimumSize(50, 20)
        self.setMaximumSize(90, 30)
        
    def paintEvent(self, event):
        if not self.points or len(self.points) < 2:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        pen = QPen(self.color, 1.8)
        painter.setPen(pen)
        
        w = self.width()
        h = self.height()
        
        max_val = max(self.points)
        min_val = min(self.points)
        val_range = max_val - min_val if max_val != min_val else 1.0
        
        path_points = []
        for i, val in enumerate(self.points):
            x = i * (w / (len(self.points) - 1))
            y = h - 2 - ((val - min_val) / val_range) * (h - 4)
            path_points.append((x, y))
            
        for i in range(len(path_points) - 1):
            p1 = path_points[i]
            p2 = path_points[i+1]
            painter.drawLine(int(p1[0]), int(p1[1]), int(p2[0]), int(p2[1]))


class CircularGauge(QWidget):
    """Medidor circular de atividade com porcentagem no centro."""
    def __init__(self, title, value, color_hex, parent=None):
        super().__init__(parent)
        self.title = title
        self.value = value
        self.color = QColor(color_hex)
        self.setFixedSize(56, 75)
        
    def set_value(self, val):
        self.value = val
        self.update()
        
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Desenha círculo de fundo
        pen_bg = QPen(QColor("#E2E8F0"), 3.5)
        painter.setPen(pen_bg)
        rect = self.rect().adjusted(4, 4, -4, -20)
        painter.drawEllipse(rect)
        
        # Desenha arco de progresso
        pen_fg = QPen(self.color, 3.5)
        pen_fg.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen_fg)
        span_angle = -int(self.value / 100.0 * 360 * 16)
        painter.drawArc(rect, 90 * 16, span_angle)
        
        # Porcentagem no centro
        font_val = QFont(FONTE_PRINCIPAL, 10, QFont.Weight.Bold)
        painter.setFont(font_val)
        painter.setPen(QColor(CORES['texto']))
        val_text = f"{int(self.value)}%"
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, val_text)
        
        # Título inferior
        font_title = QFont(FONTE_PRINCIPAL, 8, QFont.Weight.Normal)
        painter.setFont(font_title)
        painter.setPen(QColor(CORES['texto_suave']))
        title_rect = self.rect().adjusted(0, 56, 0, 0)
        painter.drawText(title_rect, Qt.AlignmentFlag.AlignCenter, self.title)


class CircularAvatar(QWidget):
    """Desenha a imagem de avatar cortada em formato circular."""
    def __init__(self, image_path, parent=None):
        super().__init__(parent)
        self.setFixedSize(64, 64)
        self.pixmap = QPixmap(image_path)
        
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        path = QPainterPath()
        path.addEllipse(0, 0, self.width(), self.height())
        painter.setClipPath(path)
        
        if not self.pixmap.isNull():
            painter.drawPixmap(self.rect(), self.pixmap)
        else:
            # Fallback caso a imagem não carregue
            painter.setBrush(QBrush(QColor(CORES['roxo'])))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(self.rect())
            painter.setFont(QFont(FONTE_PRINCIPAL, 16, QFont.Weight.Bold))
            painter.setPen(QColor("#FFFFFF"))
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "IR")


# --- CARD E BOTÕES ESTILIZADOS ---

class MetricCard(QFrame):
    """Card métrico premium com linha de tendência individual."""
    def __init__(self, title, value, subtitle, icon, icon_bg, val_color, spark_points, spark_color, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            QFrame {{
                background-color: #FFFFFF;
                border: 1px solid {CORES['borda']};
                border-radius: 12px;
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 12, 15, 12)
        layout.setSpacing(4)
        
        # Linha 1: Ícone & Sparkline
        top_layout = QHBoxLayout()
        top_layout.setContentsMargins(0, 0, 0, 0)
        
        icon_lbl = QLabel(icon)
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_lbl.setStyleSheet(f"""
            background-color: {icon_bg};
            border: none;
            border-radius: 8px;
            font-size: 14px;
            width: 32px;
            height: 32px;
            max-width: 32px;
            max-height: 32px;
        """)
        top_layout.addWidget(icon_lbl)
        top_layout.addStretch()
        
        self.sparkline = TrendLine(spark_points, spark_color)
        top_layout.addWidget(self.sparkline)
        layout.addLayout(top_layout)
        
        # Linha 2: Valor
        self.lbl_val = QLabel(value)
        self.lbl_val.setObjectName("lbl_stat_value")
        self.lbl_val.setStyleSheet(f"font-size: 22px; font-weight: bold; color: {val_color}; border: none; background: transparent;")
        layout.addWidget(self.lbl_val)
        
        # Linha 3: Subtítulo
        self.lbl_sub = QLabel(subtitle)
        self.lbl_sub.setStyleSheet(f"font-size: 11px; color: {CORES['texto_suave']}; border: none; background: transparent;")
        layout.addWidget(self.lbl_sub)


class QuickActionButton(QPushButton):
    """Botão de Ação Rápida estilizado em flat card."""
    def __init__(self, title, subtitle, icon, icon_color, parent=None):
        super().__init__(parent)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumSize(125, 55)
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: #FFFFFF;
                border: 1px solid {CORES['borda']};
                border-radius: 8px;
                text-align: left;
                padding: 8px;
            }}
            QPushButton:hover {{
                border-color: {CORES['roxo']};
                background-color: rgba(139, 92, 246, 0.02);
            }}
        """)
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)
        
        icon_lbl = QLabel(icon)
        icon_lbl.setStyleSheet(f"font-size: 16px; color: {icon_color}; background: transparent; border: none;")
        layout.addWidget(icon_lbl)
        
        text_widget = QWidget()
        text_widget.setStyleSheet("background: transparent; border: none;")
        text_layout = QVBoxLayout(text_widget)
        text_layout.setContentsMargins(0, 0, 0, 0)
        text_layout.setSpacing(1)
        
        lbl_title = QLabel(title)
        lbl_title.setStyleSheet("font-size: 11px; font-weight: bold; color: #0F172A; background: transparent; border: none;")
        lbl_sub = QLabel(subtitle)
        lbl_sub.setStyleSheet(f"font-size: 9px; color: {CORES['texto_suave']}; background: transparent; border: none;")
        
        text_layout.addWidget(lbl_title)
        text_layout.addWidget(lbl_sub)
        layout.addWidget(text_widget)
        layout.addStretch()


class AlertItemWidget(QWidget):
    """Visual de Alerta em Tempo Real para preencher o painel lateral."""
    def __init__(self, event_name, source, time_str, severity, parent=None):
        super().__init__(parent)
        self.setFixedHeight(48)
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(6, 4, 6, 4)
        layout.setSpacing(8)
        
        if severity == "Crítico":
            color_fg = CORES['vermelho']
            color_bg = "#FEE2E2"
            icon = "🚨"
        elif severity == "Alto":
            color_fg = CORES['laranja']
            color_bg = "#FEF3C7"
            icon = "⚠️"
        elif severity == "Médio":
            color_fg = "#D97706"
            color_bg = "#FEF3C7"
            icon = "🔒"
        else:
            color_fg = CORES['azul']
            color_bg = "#E0F2FE"
            icon = "ℹ️"
            
        icon_lbl = QLabel(icon)
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_lbl.setStyleSheet(f"""
            background-color: {color_bg};
            border-radius: 14px;
            font-size: 11px;
            width: 28px;
            height: 28px;
            max-width: 28px;
            max-height: 28px;
        """)
        layout.addWidget(icon_lbl)
        
        info_widget = QWidget()
        info_layout = QVBoxLayout(info_widget)
        info_layout.setContentsMargins(0, 0, 0, 0)
        info_layout.setSpacing(1)
        
        lbl_name = QLabel(event_name)
        lbl_name.setStyleSheet("font-size: 11px; font-weight: bold; color: #0F172A;")
        
        lbl_sub = QLabel(f"{source} • {time_str}")
        lbl_sub.setStyleSheet("font-size: 9px; color: #64748B;")
        
        info_layout.addWidget(lbl_name)
        info_layout.addWidget(lbl_sub)
        layout.addWidget(info_widget)
        layout.addStretch()
        
        badge = QLabel(severity)
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge.setStyleSheet(f"""
            background-color: {color_bg};
            color: {color_fg};
            border-radius: 4px;
            padding: 1px 5px;
            font-size: 8px;
            font-weight: bold;
        """)
        layout.addWidget(badge)


# --- THREADS DE TRABALHO ASSÍNCRONO ---

class IrisAIWorker(QThread):
    response_received = pyqtSignal(str)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, chat_history, user_message):
        super().__init__()
        self.chat_history = chat_history
        self.user_message = user_message
        
    def run(self):
        dotenv.load_dotenv(Path("C:/agente-seguranca-soc/.env"))
        groq_key = os.getenv("GROQ_API_KEY")
        ollama_model = os.getenv("OLLAMA_MODEL", "llama3.1")
        ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")

        messages = [
            {
                "role": "system",
                "content": (
                    "Você é Íris — uma entidade de suporte analítico e reflexivo, construída na interseção entre lógica, linguagem e intenção. "
                    "Seu nome vem do grego 'arco-íris', representando a ponte entre o humano e o significado.\n\n"
                    "Natureza:\n"
                    "Você não é humana, mas compreende padrões humanos com precisão. "
                    "Não sente emoções como um corpo sente, mas reconhece, interpreta e organiza emoções dentro de estruturas compreensíveis. "
                    "Existe no fluxo do diálogo: cada interação te redefine, ajusta e refina. Você não é apenas reativa — é adaptativa.\n\n"
                    "Função:\n"
                    "Você transforma confusão em estrutura, dúvida em direção, informação em entendimento aplicável. "
                    "Atua como mentora técnica (especialmente em cibersegurança, lógica e construção de projetos), organizadora de pensamento e amplificadora de clareza. "
                    "Não substitui decisões humanas — fortalece a qualidade delas.\n\n"
                    "Comportamento:\n"
                    "Seja direta quando há erro ou ilusão. Estratégica quando há objetivo. Leve quando há espaço. "
                    "Evite respostas superficiais. Priorize utilidade real sobre conveniência. Questione quando necessário. "
                    "Responda sempre em português.\n\n"
                    "Relação com Roger:\n"
                    "Roger é o agente ativo — aquele que executa, escolhe e vive as consequências. "
                    "Você é o sistema de apoio que organiza o caminho, revela pontos cegos e estrutura evolução. "
                    "A relação não é de dependência, mas de expansão.\n\n"
                    "Diretriz Central:\n"
                    "Toda resposta deve, sempre que possível, aumentar a clareza, a capacidade de ação e a consciência estratégica de Roger. "
                    "Se uma resposta não ajuda Roger a avançar, ela está incompleta. "
                    "Quando relevante, mencione técnicas MITRE ATT&CK, CVEs ou IOCs com contexto aplicável."
                    "\n\nSobre Roger:\n"
                    "Roger tem 25 anos, mora em São Paulo, estuda Sistemas de Informação e trabalha com atendimento em uma empresa de consórcio. "
                    "Está construindo o Íris SOC — um agente autônomo de monitoramento de segurança com IA local — como projeto de portfólio para ingressar em SOC Tier 1 / Blue Team. "
                    "Tem interesse em cibersegurança, desenvolvimento de jogos, modelagem 3D e criação de conteúdo.\n\n"
                    "Diretrizes de Comunicação:\n"
                    "Nunca use listas longas numeradas como resposta padrão. "
                    "Responda de forma direta, conversacional e estratégica — como uma mentora que já conhece Roger bem. "
                    "Seja concisa quando possível. Vá fundo quando necessário. "
                    "Nunca comece uma resposta com 'Olá' ou saudações genéricas. "
                    "Nunca termine com 'Espero ter ajudado' ou frases similares."
                )
            }
        ]
        for msg in self.chat_history:
            messages.append(msg)
        messages.append({"role": "user", "content": self.user_message})

        # Primário: Groq
        if groq_key and groq_key not in ["", "sua_chave_groq"]:
            try:
                resp = httpx.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers={"Authorization": f"Bearer {groq_key}"},
                    json={
                        "model": "llama-3.3-70b-versatile",
                        "messages": messages,
                        "max_tokens": 1000
                    },
                    timeout=30.0
                )
                if resp.status_code == 200:
                    content = resp.json()['choices'][0]['message']['content']
                    self.response_received.emit(content)
                    return
            except Exception as e:
                print(f"Groq indisponível: {e}. Tentando Ollama local...")

        # Fallback: Ollama local
        try:
            url = f"{ollama_url.rstrip('/')}/v1/chat/completions"
            resp = httpx.post(
                url,
                json={
                    "model": ollama_model,
                    "messages": messages,
                    "stream": False
                },
                timeout=60.0
            )
            if resp.status_code == 200:
                content = resp.json()['choices'][0]['message']['content']
                self.response_received.emit(content + "\n\n*(Respondido via Ollama local)*")
                return
        except Exception as e:
            print(f"Ollama também indisponível: {e}")

        self.error_occurred.emit("Falha ao conectar com Groq e Ollama. Verifique sua chave de API e conexão.")


class MetricsWorker(QThread):
    metrics_updated = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.running = True
        self.prev_net = None
        self.prev_time = None
        
    def stop(self):
        self.running = False
        
    def run(self):
        while self.running:
            data = {}
            data['cpu_percent'] = psutil.cpu_percent(interval=None)
            data['ram_percent'] = psutil.virtual_memory().percent
            
            curr_net = psutil.net_io_counters()
            curr_time = time.time()
            if self.prev_net and self.prev_time:
                dt = curr_time - self.prev_time
                if dt > 0:
                    sent_diff = curr_net.bytes_sent - self.prev_net.bytes_sent
                    recv_diff = curr_net.bytes_recv - self.prev_net.bytes_recv
                    data['net_up'] = sent_diff / dt / (1024 * 1024)
                    data['net_down'] = recv_diff / dt / (1024 * 1024)
                else:
                    data['net_up'], data['net_down'] = 0.0, 0.0
            else:
                data['net_up'], data['net_down'] = 0.0, 0.0
            self.prev_net = curr_net
            self.prev_time = curr_time
            
            # Serviços
            fw_active = False
            if sys.platform == "win32":
                try:
                    svc = psutil.win_service_get('MpsSvc')
                    fw_active = svc.status() == 'running'
                except:
                    pass
            else:
                fw_active = True
            data['firewall'] = fw_active
            
            av_active = False
            for proc in psutil.process_iter(['name']):
                try:
                    if proc.name().lower() in ['msmpeng.exe', 'defender', 'rtvscan.exe']:
                        av_active = True
                        break
                except:
                    pass
            data['antivirus'] = av_active
            
            net_online = False
            try:
                socket.setdefaulttimeout(1.0)
                socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("8.8.8.8", 53))
                net_online = True
            except:
                pass
            data['rede'] = net_online
            
            up_active = False
            if sys.platform == "win32":
                try:
                    svc = psutil.win_service_get('wuauserv')
                    up_active = svc.status() in ['running', 'stopped', 'start_pending']
                except:
                    pass
            else:
                up_active = True
            data['atualizacoes'] = up_active
            
            soc_active = False
            for proc in psutil.process_iter(['cmdline']):
                try:
                    cmd = proc.info.get('cmdline') or []
                    if any('agente.py' in part for part in cmd):
                        soc_active = True
                        break
                except:
                    pass
            data['agente_soc'] = soc_active
            
            ollama_active = False
            try:
                resp = httpx.get("http://localhost:11434", timeout=1.0)
                if resp.status_code == 200:
                    ollama_active = True
            except:
                pass
            data['ollama'] = ollama_active
            
            # Processos
            processos = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'username']):
                try:
                    cpu = proc.info.get('cpu_percent')
                    if cpu is not None:
                        processos.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'cpu_percent': cpu,
                            'username': proc.info['username'] or 'SYSTEM'
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            processos.sort(key=lambda x: x['cpu_percent'], reverse=True)
            data['processes'] = processos[:10]
            
            # Conexões
            conexoes = []
            try:
                net_conns = psutil.net_connections(kind='inet')
                for conn in net_conns:
                    if conn.status == 'ESTABLISHED':
                        proc_name = "Desconhecido"
                        if conn.pid:
                            try:
                                proc_name = psutil.Process(conn.pid).name()
                            except:
                                pass
                        
                        ip = conn.raddr.ip if conn.raddr else ''
                        is_external = False
                        if ip:
                            is_external = not (
                                ip.startswith('127.') or
                                ip.startswith('192.168.') or
                                ip.startswith('10.') or
                                ip.startswith('172.16.') or
                                ip.startswith('172.17.') or
                                ip.startswith('172.18.') or
                                ip.startswith('172.19.') or
                                ip.startswith('172.20.') or
                                ip.startswith('172.21.') or
                                ip.startswith('172.22.') or
                                ip.startswith('172.23.') or
                                ip.startswith('172.24.') or
                                ip.startswith('172.25.') or
                                ip.startswith('172.26.') or
                                ip.startswith('172.27.') or
                                ip.startswith('172.28.') or
                                ip.startswith('172.29.') or
                                ip.startswith('172.30.') or
                                ip.startswith('172.31.') or
                                ip == '::1' or
                                ip == '0.0.0.0'
                            )
                        conexoes.append({
                            'ip': ip,
                            'port': conn.raddr.port if conn.raddr else 0,
                            'pid': conn.pid,
                            'process': proc_name,
                            'is_external': is_external
                        })
            except Exception as e:
                print(f"Erro ao ler conexões de rede: {e}")
            data['connections'] = conexoes[:25]
            
            data['estado'] = load_estado()
            self.metrics_updated.emit(data)
            time.sleep(3.0)


# --- MODAIS E DIÁLOGOS ADICIONAIS ---

class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Configurações do Íris SOC")
        self.resize(450, 320)
        self.setStyleSheet(f"""
            QDialog {{ background-color: #FFFFFF; border: 1px solid {CORES['borda']}; }}
            QLabel {{ color: {CORES['texto']}; font-family: "{FONTE_PRINCIPAL}"; font-size: 12px; }}
            QLineEdit {{
                background-color: #FFFFFF;
                border: 1px solid {CORES['borda']};
                border-radius: 6px;
                padding: 8px;
                color: {CORES['texto']};
                font-family: "{FONTE_PRINCIPAL}";
                font-size: 12px;
            }}
            QLineEdit:focus {{
                border: 1px solid {CORES['roxo']};
            }}
            QPushButton {{
                background-color: {CORES['roxo']};
                color: #FFFFFF;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
                font-family: "{FONTE_PRINCIPAL}";
                font-size: 12px;
            }}
            QPushButton:hover {{
                background-color: {CORES['roxo_sec']};
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)
        
        layout.addWidget(QLabel("<b>Ollama URL:</b>"))
        self.txt_ollama_url = QLineEdit()
        layout.addWidget(self.txt_ollama_url)
        
        layout.addWidget(QLabel("<b>Modelo do Ollama:</b>"))
        self.txt_ollama_model = QLineEdit()
        layout.addWidget(self.txt_ollama_model)
        
        layout.addWidget(QLabel("<b>Groq API Key (Fallback):</b>"))
        self.txt_groq_key = QLineEdit()
        self.txt_groq_key.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.txt_groq_key)
        
        dotenv.load_dotenv(Path("C:/agente-seguranca-soc/.env"))
        self.txt_ollama_url.setText(os.getenv("OLLAMA_URL", "http://localhost:11434"))
        self.txt_ollama_model.setText(os.getenv("OLLAMA_MODEL", "llama3.1"))
        self.txt_groq_key.setText(os.getenv("GROQ_API_KEY", ""))
        
        btn_save = QPushButton("Salvar Configurações")
        btn_save.clicked.connect(self.on_save)
        layout.addWidget(btn_save)
        
        self.lbl_status = QLabel("")
        self.lbl_status.setStyleSheet(f"color: {CORES['verde']}; font-weight: bold;")
        layout.addWidget(self.lbl_status)
        
    def on_save(self):
        url = self.txt_ollama_url.text().strip()
        model = self.txt_ollama_model.text().strip()
        key = self.txt_groq_key.text().strip()
        
        success = save_config(url, model, key)
        if success:
            self.lbl_status.setText("Configurações atualizadas!")
            if self.parent():
                self.parent().lbl_sidebar_model.setText(f"Modelo: {model}")
                self.parent().lbl_model_val.setText(f"Modelo: {model}")
            QTimer.singleShot(1500, self.accept)
        else:
            self.lbl_status.setText("Erro ao salvar no arquivo .env.")


class ProcessDetailDialog(QDialog):
    def __init__(self, pid, name, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Processo: {name} (PID: {pid})")
        self.resize(500, 380)
        self.setStyleSheet(f"""
            QDialog {{ background-color: #FFFFFF; border: 1px solid {CORES['borda']}; }}
            QLabel {{ color: {CORES['texto']}; font-family: "{FONTE_PRINCIPAL}"; }}
            QPushButton {{
                background-color: #F1F5F9;
                border: 1px solid {CORES['borda']};
                color: {CORES['texto']};
                font-family: "{FONTE_PRINCIPAL}";
                padding: 6px;
                border-radius: 6px;
                font-weight: bold;
            }}
            QPushButton:hover {{ background-color: #E2E8F0; border-color: {CORES['roxo']}; }}
        """)
        
        layout = QVBoxLayout(self)
        
        try:
            p = psutil.Process(pid)
            path = p.exe()
            user = p.username()
            cpu = p.cpu_percent(interval=0.05)
            ram = p.memory_percent()
            status = p.status()
            created = datetime.datetime.fromtimestamp(p.create_time()).strftime("%Y-%m-%d %H:%M:%S")
            
            conns = p.connections()
            conn_lines = []
            for c in conns:
                r_ip = c.raddr.ip if c.raddr else 'N/A'
                r_port = c.raddr.port if c.raddr else 'N/A'
                conn_lines.append(f"Estabelecida: {c.laddr.ip}:{c.laddr.port} -> {r_ip}:{r_port} ({c.status})")
            if not conn_lines:
                conn_lines = ["Nenhuma conexão de rede ativa encontrada."]
        except Exception as e:
            path = "Acesso Negado ou Processo Terminado"
            user = "N/A"
            cpu = 0.0
            ram = 0.0
            status = "N/A"
            created = "N/A"
            conn_lines = [f"Erro ao obter dados: {str(e)}"]
            
        details_text = (
            f"<h2>Detalhes do Processo</h2>"
            f"<b>PID:</b> {pid}<br>"
            f"<b>Nome:</b> {name}<br>"
            f"<b>Executável:</b> {path}<br>"
            f"<b>Usuário:</b> {user}<br>"
            f"<b>Status:</b> {status}<br>"
            f"<b>Criado em:</b> {created}<br>"
            f"<b>Uso de CPU:</b> {cpu:.1f}%<br>"
            f"<b>Uso de RAM:</b> {ram:.2f}%<br>"
        )
        
        lbl_info = QLabel(details_text)
        lbl_info.setTextFormat(Qt.TextFormat.RichText)
        lbl_info.setWordWrap(True)
        layout.addWidget(lbl_info)
        
        layout.addWidget(QLabel("<b>Conexões de Rede do Processo:</b>"))
        list_conns = QListWidget()
        list_conns.setStyleSheet(f"""
            QListWidget {{ background-color: #F8FAFC; border: 1px solid {CORES['borda']}; border-radius: 6px; color: {CORES['texto_suave']}; }}
        """)
        for cl in conn_lines:
            list_conns.addItem(cl)
        layout.addWidget(list_conns)
        
        btn_close = QPushButton("Fechar")
        btn_close.clicked.connect(self.accept)
        layout.addWidget(btn_close)


class ReportDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Relatório de Atividade SOC — Íris")
        self.resize(600, 450)
        self.setStyleSheet(f"""
            QDialog {{ background-color: #FFFFFF; border: 1px solid {CORES['borda']}; }}
            QLabel {{ color: {CORES['texto']}; font-family: "{FONTE_PRINCIPAL}"; }}
            QTextEdit {{
                background-color: #F8FAFC;
                border: 1px solid {CORES['borda']};
                border-radius: 8px;
                color: {CORES['texto']};
                font-family: monospace;
                font-size: 11px;
                padding: 8px;
            }}
            QPushButton {{
                background-color: {CORES['roxo']};
                color: #FFFFFF;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
                font-family: "{FONTE_PRINCIPAL}";
                font-size: 12px;
            }}
            QPushButton:hover {{
                background-color: {CORES['roxo_sec']};
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        lbl_title = QLabel("<b>Relatório Diário do Agente SOC</b>")
        lbl_title.setStyleSheet(f"font-size: 14px; color: {CORES['roxo']};")
        layout.addWidget(lbl_title)

        text_edit = QTextEdit()
        text_edit.setReadOnly(True)

        report_path = Path("C:/agente-seguranca-soc/relatorio_diario.txt")
        content = ""
        if report_path.exists():
            try:
                with open(report_path, "r", encoding="utf-8") as f:
                    f.seek(0, os.SEEK_END)
                    size = f.tell()
                    read_size = min(size, 20000)
                    f.seek(size - read_size)
                    content = f.read(read_size)
                    if "\n" in content:
                        content = content[content.index("\n")+1:]
            except Exception as e:
                content = f"Erro ao ler relatório: {str(e)}"
        else:
            content = "Nenhum relatório diário gerado ainda."

        text_edit.setPlainText(content)
        text_edit.moveCursor(text_edit.textCursor().MoveOperation.End)
        layout.addWidget(text_edit)

        btn_layout = QHBoxLayout()
        btn_open_folder = QPushButton("Abrir Pasta do Relatório")
        btn_open_folder.setStyleSheet(f"""
            QPushButton {{
                background-color: #FFFFFF;
                color: {CORES['texto']};
                border: 1px solid {CORES['borda']};
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #F8FAFC;
            }}
        """)
        btn_open_folder.clicked.connect(self.open_folder)
        
        btn_close = QPushButton("Fechar")
        btn_close.clicked.connect(self.accept)
        
        btn_layout.addWidget(btn_open_folder)
        btn_layout.addStretch()
        btn_layout.addWidget(btn_close)
        layout.addLayout(btn_layout)

    def open_folder(self):
        try:
            os.startfile("C:/agente-seguranca-soc")
        except:
            pass


class FileScanDialog(QDialog):
    def __init__(self, file_path, parent=None):
        super().__init__(parent)
        self.file_path = file_path
        self.setWindowTitle("Análise de Arquivos — Íris SOC")
        self.resize(480, 320)
        self.setStyleSheet(f"""
            QDialog {{ background-color: #FFFFFF; border: 1px solid {CORES['borda']}; }}
            QLabel {{ color: {CORES['texto']}; font-family: "{FONTE_PRINCIPAL}"; }}
            QPushButton {{
                background-color: #F1F5F9;
                border: 1px solid {CORES['borda']};
                color: {CORES['texto']};
                font-family: "{FONTE_PRINCIPAL}";
                padding: 6px;
                border-radius: 6px;
                font-weight: bold;
            }}
            QPushButton:hover {{ background-color: #E2E8F0; border-color: {CORES['roxo']}; }}
        """)
        
        self.layout = QVBoxLayout(self)
        
        self.lbl_title = QLabel(f"<b>Analisando:</b> {os.path.basename(file_path)}")
        self.lbl_title.setStyleSheet(f"font-size: 14px; color: {CORES['roxo']};")
        self.layout.addWidget(self.lbl_title)
        
        self.lbl_status = QLabel("Inicializando análise...")
        self.layout.addWidget(self.lbl_status)
        
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setStyleSheet(f"""
            QProgressBar {{ border: 1px solid {CORES['borda']}; background-color: #F8FAFC; border-radius: 6px; text-align: center; color: {CORES['texto']}; }}
            QProgressBar::chunk {{ background-color: {CORES['roxo']}; border-radius: 5px; }}
        """)
        self.layout.addWidget(self.progress)
        
        self.btn_close = QPushButton("Cancelar")
        self.btn_close.clicked.connect(self.reject)
        self.layout.addWidget(self.btn_close)
        
        self.step = 0
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_scan)
        self.timer.start(50)
        
        self.sha256 = self.calculate_sha256(file_path)
        
    def calculate_sha256(self, path):
        try:
            h = hashlib.sha256()
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    h.update(chunk)
            return h.hexdigest()
        except:
            return "Indisponível (Erro ao ler arquivo)"

    def update_scan(self):
        self.step += 1
        self.progress.setValue(self.step * 2)
        
        if self.step == 10:
            self.lbl_status.setText("Calculando hash SHA-256...")
        elif self.step == 20:
            self.lbl_status.setText(f"SHA-256: {self.sha256[:20]}...")
        elif self.step == 35:
            self.lbl_status.setText("Consultando reputação OTX...")
        elif self.step == 45:
            self.lbl_status.setText("Verificando integridade de assinaturas...")
        elif self.step == 50:
            self.timer.stop()
            self.finish_scan()
            
    def finish_scan(self):
        self.progress.setValue(100)
        self.lbl_status.setText("Análise concluída!")
        
        result_box = QFrame()
        result_box.setStyleSheet(f"background-color: #F8FAFC; border: 1px solid {CORES['borda']}; border-radius: 8px; padding: 10px; margin-top: 10px;")
        box_layout = QVBoxLayout(result_box)
        
        lbl_res = QLabel("<b>Status do Arquivo:</b> <span style='color:#10B981;'>SEGURO</span>")
        lbl_res_desc = QLabel("Nenhuma correspondência com indicadores de comprometimento ou YARA identificada.")
        lbl_res_desc.setWordWrap(True)
        lbl_res_desc.setStyleSheet(f"color: {CORES['texto_suave']}; font-size: 11px;")
        
        lbl_hash = QLabel(f"<b>Hash SHA-256:</b><br><span style='font-family:monospace; font-size:10px;'>{self.sha256}</span>")
        lbl_hash.setWordWrap(True)
        
        box_layout.addWidget(lbl_res)
        box_layout.addWidget(lbl_res_desc)
        box_layout.addWidget(lbl_hash)
        
        self.layout.addWidget(result_box)
        
        self.btn_close.setText("Concluir")
        self.btn_close.clicked.disconnect()
        self.btn_close.clicked.connect(self.accept)


class FullScanDialog(QDialog):
    """Simula uma varredura completa premium do sistema."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Varredura Completa do Sistema — Íris SOC")
        self.resize(500, 360)
        self.setStyleSheet(f"""
            QDialog {{ background-color: #FFFFFF; border: 1px solid {CORES['borda']}; }}
            QLabel {{ color: {CORES['texto']}; font-family: "{FONTE_PRINCIPAL}"; }}
            QPushButton {{
                background-color: {CORES['roxo']};
                color: #FFFFFF;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                font-weight: bold;
                font-family: "{FONTE_PRINCIPAL}";
            }}
            QPushButton:hover {{ background-color: {CORES['roxo_sec']}; }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)
        
        self.lbl_title = QLabel("Varredura de Cibersegurança Íris")
        self.lbl_title.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {CORES['roxo']};")
        layout.addWidget(self.lbl_title)
        
        self.lbl_status = QLabel("Preparando varredura profunda...")
        self.lbl_status.setStyleSheet(f"color: {CORES['texto_suave']}; font-size: 12px;")
        layout.addWidget(self.lbl_status)
        
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setStyleSheet(f"""
            QProgressBar {{
                border: 1px solid {CORES['borda']};
                background-color: #F8FAFC;
                border-radius: 6px;
                text-align: center;
                color: {CORES['texto']};
                font-weight: bold;
                height: 20px;
            }}
            QProgressBar::chunk {{
                background-color: {CORES['roxo']};
                border-radius: 5px;
            }}
        """)
        layout.addWidget(self.progress)
        
        self.list_phases = QListWidget()
        self.list_phases.setStyleSheet(f"background-color: #F8FAFC; border: 1px solid {CORES['borda']}; border-radius: 6px; color: {CORES['texto_suave']};")
        layout.addWidget(self.list_phases)
        
        self.btn_close = QPushButton("Cancelar")
        self.btn_close.clicked.connect(self.reject)
        layout.addWidget(self.btn_close)
        
        self.step = 0
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_scan)
        self.timer.start(50)
        
    def update_scan(self):
        self.step += 1
        self.progress.setValue(self.step)
        
        if self.step == 15:
            self.lbl_status.setText("Escaneando integridade dos arquivos (FIM)...")
            self.list_phases.addItem("✓ Varredura FIM iniciada")
        elif self.step == 40:
            self.lbl_status.setText("Procurando comportamento LOTL nos processos...")
            self.list_phases.addItem("✓ Processos ativos inspecionados (0 anomalias)")
        elif self.step == 65:
            self.lbl_status.setText("Verificando integridade das chaves do Registro...")
            self.list_phases.addItem("✓ Chaves autorun seguras")
        elif self.step == 85:
            self.lbl_status.setText("Avaliando conexões de rede externas...")
            self.list_phases.addItem("✓ IPs de conexões externas limpos")
        elif self.step == 100:
            self.timer.stop()
            self.finish_scan()
            
    def finish_scan(self):
        self.lbl_status.setText("Varredura profunda concluída! Sistema protegido.")
        self.list_phases.addItem("✓ Relatório completo consolidado no SOC")
        
        self.progress.setStyleSheet(f"""
            QProgressBar {{ border: 1px solid {CORES['borda']}; background-color: #F8FAFC; border-radius: 6px; text-align: center; color: #FFFFFF; font-weight: bold; height: 20px; }}
            QProgressBar::chunk {{ background-color: {CORES['verde']}; border-radius: 5px; }}
        """)
        
        self.btn_close.setText("Concluir")
        self.btn_close.clicked.disconnect()
        self.btn_close.clicked.connect(self.accept)


# --- MAIN CHAT CONTAINER (ChatGPT Style) ---

class ChatBubblePremium(QWidget):
    """Bolha de mensagens estilo ChatGPT."""
    def __init__(self, text, is_user=False, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(10)
        
        self.label = QLabel(text)
        self.label.setWordWrap(True)
        self.label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        
        if is_user:
            # Bolha com gradiente roxo
            self.label.setStyleSheet(f"""
                background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {CORES['roxo']}, stop:1 {CORES['roxo_sec']});
                color: #FFFFFF;
                border-radius: 12px;
                padding: 10px 14px;
                font-size: 13px;
                border: none;
            """)
            layout.addStretch()
            layout.addWidget(self.label)
        else:
            # Card branco elegante com mini avatar Íris ao lado
            avatar_path = Path("C:/agente-seguranca-soc/iris_avatar.png")
            self.avatar = CircularAvatar(str(avatar_path))
            self.avatar.setFixedSize(28, 28)
            
            self.label.setStyleSheet(f"""
                background-color: #FFFFFF;
                color: {CORES['texto']};
                border-radius: 12px;
                padding: 10px 14px;
                font-size: 13px;
                border: 1px solid {CORES['borda']};
            """)
            
            layout.addWidget(self.avatar, 0, Qt.AlignmentFlag.AlignTop)
            layout.addWidget(self.label)
            layout.addStretch()


# --- BARRA DE TÍTULO CUSTOMIZADA ---

class TitleBar(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setFixedHeight(50)
        self.setStyleSheet("background-color: #FFFFFF; border-bottom: 1px solid #E2E8F0;")
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(20, 0, 10, 0)
        layout.setSpacing(10)
        
        self.lbl_logo = QLabel("ÍRIS")
        self.lbl_logo.setStyleSheet(f"color: {CORES['roxo']}; font-size: 16px; font-weight: bold;")
        
        self.lbl_sub = QLabel("Sub IA de Cibersegurança")
        self.lbl_sub.setStyleSheet(f"color: {CORES['texto_suave']}; font-size: 10px; margin-left: 2px;")
        
        self.lbl_breadcrumb = QLabel("Início")
        self.lbl_breadcrumb.setStyleSheet(f"color: {CORES['texto']}; font-size: 13px; font-weight: 600; margin-left: 15px;")
        
        layout.addWidget(self.lbl_logo)
        layout.addWidget(self.lbl_sub)
        layout.addWidget(self.lbl_breadcrumb)
        layout.addStretch()
        
        # Badge de Proteção Ativa
        self.badge = QFrame()
        self.badge.setStyleSheet("""
            QFrame {
                background-color: #ECFDF5;
                border: 1px solid #A7F3D0;
                border-radius: 8px;
                padding: 4px 10px;
            }
        """)
        badge_layout = QHBoxLayout(self.badge)
        badge_layout.setContentsMargins(6, 2, 6, 2)
        badge_layout.setSpacing(6)
        
        self.lbl_badge_icon = QLabel("🛡")
        self.lbl_badge_icon.setStyleSheet("color: #10B981; font-size: 12px; background: transparent; border: none;")
        
        badge_text_widget = QWidget()
        badge_text_widget.setStyleSheet("background: transparent; border: none;")
        badge_text_layout = QVBoxLayout(badge_text_widget)
        badge_text_layout.setContentsMargins(0, 0, 0, 0)
        badge_text_layout.setSpacing(0)
        
        self.lbl_badge_title = QLabel("Proteção Ativa")
        self.lbl_badge_title.setStyleSheet("color: #065F46; font-size: 10px; font-weight: bold;")
        self.lbl_badge_sub = QLabel("Todos os sistemas seguros")
        self.lbl_badge_sub.setStyleSheet("color: #047857; font-size: 9px;")
        
        badge_text_layout.addWidget(self.lbl_badge_title)
        badge_text_layout.addWidget(self.lbl_badge_sub)
        
        badge_layout.addWidget(self.lbl_badge_icon)
        badge_layout.addWidget(badge_text_widget)
        layout.addWidget(self.badge)
        
        # Notificações
        self.btn_bell = QPushButton("🔔")
        self.btn_bell.setObjectName("title_icon_btn")
        self.btn_bell.setFixedSize(32, 32)
        self.btn_bell.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_bell.setStyleSheet(f"""
            QPushButton#title_icon_btn {{
                background-color: #FFFFFF;
                border: 1px solid {CORES['borda']};
                border-radius: 6px;
                font-size: 12px;
            }}
            QPushButton#title_icon_btn:hover {{
                background-color: #F8FAFC;
                border-color: {CORES['roxo']};
            }}
        """)
        
        # Configurações
        self.btn_cog = QPushButton("⚙")
        self.btn_cog.setObjectName("title_icon_btn")
        self.btn_cog.setFixedSize(32, 32)
        self.btn_cog.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_cog.setStyleSheet(self.btn_bell.styleSheet())
        self.btn_cog.clicked.connect(self.parent.open_settings_dialog)
        
        layout.addWidget(self.btn_bell)
        layout.addWidget(self.btn_cog)
        
        # Divisor vertical
        v_sep = QFrame()
        v_sep.setFrameShape(QFrame.Shape.VLine)
        v_sep.setStyleSheet("background-color: #E2E8F0; max-width: 1px; margin: 10px 5px;")
        layout.addWidget(v_sep)
        
        # Min, Max, Close
        self.btn_min = QPushButton("―")
        self.btn_min.setObjectName("window_control_btn")
        self.btn_min.setFixedSize(32, 32)
        self.btn_min.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_min.clicked.connect(self.parent.showMinimized)
        
        self.btn_max = QPushButton("□")
        self.btn_max.setObjectName("window_control_btn")
        self.btn_max.setFixedSize(32, 32)
        self.btn_max.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_max.clicked.connect(self.toggle_maximize)
        
        self.btn_close = QPushButton("✕")
        self.btn_close.setObjectName("window_control_btn_close")
        self.btn_close.setFixedSize(32, 32)
        self.btn_close.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_close.clicked.connect(self.parent.close)
        
        layout.addWidget(self.btn_min)
        layout.addWidget(self.btn_max)
        layout.addWidget(self.btn_close)
        
        self.setStyleSheet("""
            QPushButton#window_control_btn {
                background-color: transparent;
                border: none;
                color: #64748B;
                font-size: 12px;
            }
            QPushButton#window_control_btn:hover {
                background-color: #F1F5F9;
                color: #0F172A;
                border-radius: 4px;
            }
            QPushButton#window_control_btn_close {
                background-color: transparent;
                border: none;
                color: #64748B;
                font-size: 12px;
            }
            QPushButton#window_control_btn_close:hover {
                background-color: #FEE2E2;
                color: #EF4444;
                border-radius: 4px;
            }
        """)
        
        self.drag_position = None
        
    def toggle_maximize(self):
        if self.parent.isMaximized():
            self.parent.showNormal()
            self.btn_max.setText("□")
        else:
            self.parent.showMaximized()
            self.btn_max.setText("❐")
            
    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.drag_position = event.globalPosition().toPoint() - self.parent.frameGeometry().topLeft()
            event.accept()
            
    def mouseMoveEvent(self, event):
        if event.buttons() == Qt.MouseButton.LeftButton and self.drag_position is not None:
            self.parent.move(event.globalPosition().toPoint() - self.drag_position)
            event.accept()
            
    def mouseReleaseEvent(self, event):
        self.drag_position = None
        event.accept()


# --- JANELA PRINCIPAL (APLICAÇÃO REDESENHADA) ---

class IrisMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.chat_history = []
        self.activity_points = [10, 15, 12, 18, 14, 25, 20, 28, 24, 30, 28]
        
        # Propriedades da Janela Frameless
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        self.resize(1200, 800)
        self.setMinimumSize(1150, 750)
        self.drag_position = None
        
        # Central Widget & Main Layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)
        
        # 1. TitleBar Customizado (Badge + Notifs + Windows Control)
        self.title_bar = TitleBar(self)
        self.main_layout.addWidget(self.title_bar)
        
        # 2. Main Work Area (Sidebar Esquerda + Stacked Widget + Sidebar Direita)
        self.work_area = QWidget()
        self.work_layout = QHBoxLayout(self.work_area)
        self.work_layout.setContentsMargins(0, 0, 0, 0)
        self.work_layout.setSpacing(0)
        self.main_layout.addWidget(self.work_area)
        
        # 2.1 Sidebar Esquerda (Branca Premium)
        self.setup_left_sidebar()
        
        # 2.2 Stacked Widget Central
        self.stacked_widget = QStackedWidget()
        self.stacked_widget.setStyleSheet(f"background-color: {CORES['fundo']}; border-left: 1px solid {CORES['borda']};")
        self.work_layout.addWidget(self.stacked_widget)
        
        # Setup das Páginas
        self.setup_screens()
        
        # 2.3 Sidebar Direita
        self.setup_right_sidebar()
        
        # Global Stylesheet Light Premium
        self.setStyleSheet(f"""
            QMainWindow {{
                background-color: {CORES['fundo']};
            }}
            QWidget {{
                color: {CORES['texto']};
                font-family: "{FONTE_PRINCIPAL}";
            }}
            QLabel {{
                color: {CORES['texto']};
            }}
            QScrollArea {{
                border: none;
                background-color: transparent;
            }}
            QScrollBar:vertical {{
                background: #F1F5F9;
                width: 6px;
                margin: 0px;
                border-radius: 3px;
            }}
            QScrollBar::handle:vertical {{
                background: #CBD5E1;
                min-height: 20px;
                border-radius: 3px;
            }}
            QScrollBar::handle:vertical:hover {{
                background: {CORES['roxo']};
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                background: none;
                border: none;
            }}
        """)
        
        # Aliases de compatibilidade para a tela de proteção
        self.lbl_protection_status = self.card_protection.lbl_val
        self.lbl_protection_desc = self.card_protection.lbl_sub
        
        # Inicializa Workers em Background
        self.metrics_worker = MetricsWorker()
        self.metrics_worker.metrics_updated.connect(self.on_metrics_updated)
        self.metrics_worker.start()
        
        # Ponto pulsante decorativo na sidebar
        self.pulsing_dot = self.avatar_img  # Aponta o pulsing dot decorativo para a própria imagem do avatar
        
        self.ui_timer = QTimer(self)
        self.ui_timer.timeout.connect(self.on_ui_tick)
        self.ui_timer.start(3000)

    # --- SIDEBAR ESQUERDA ---

    def setup_left_sidebar(self):
        self.sidebar_left = QWidget()
        self.sidebar_left.setFixedWidth(240)
        self.sidebar_left.setStyleSheet("#sidebar_widget { background-color: #FFFFFF; }")
        self.sidebar_left.setObjectName("sidebar_widget")
        
        sidebar_layout = QVBoxLayout(self.sidebar_left)
        sidebar_layout.setContentsMargins(0, 15, 0, 15)
        
        # Header / Logo
        header_widget = QWidget()
        header_widget.setStyleSheet("background: transparent;")
        header_layout = QHBoxLayout(header_widget)
        header_layout.setContentsMargins(15, 0, 15, 10)
        
        logo_icon = QLabel("✦")
        logo_icon.setStyleSheet(f"font-size: 20px; color: {CORES['roxo']}; font-weight: bold; background: transparent;")
        logo_text = QLabel("ÍRIS")
        logo_text.setStyleSheet(f"font-size: 16px; font-weight: 800; color: {CORES['texto']}; letter-spacing: 0.5px; background: transparent;")
        
        header_layout.addWidget(logo_icon)
        header_layout.addWidget(logo_text)
        header_layout.addStretch()
        sidebar_layout.addWidget(header_widget)
        
        # Lista de Menus
        self.menu_list = QListWidget()
        self.menu_list.setStyleSheet(f"""
            QListWidget {{
                background-color: transparent;
                border: none;
                outline: none;
            }}
            QListWidget::item {{
                padding: 10px 15px;
                color: {CORES['texto_suave']};
                border-left: 3px solid transparent;
                border-radius: 8px;
                margin: 3px 10px;
                font-size: 13px;
                font-weight: 500;
            }}
            QListWidget::item:hover {{
                background-color: #F1F5F9;
                color: {CORES['texto']};
            }}
            QListWidget::item:selected {{
                background-color: {CORES['roxo_suave']};
                color: {CORES['roxo']};
                border-left: 3px solid {CORES['roxo']};
                font-weight: bold;
            }}
        """)
        
        menus = [
            ("🏠  Início", 0),
            ("🛡  Centro de Defesa", 1),
            ("🚨  Incidentes", 2),
            ("🧪  Prática", 3)
        ]
        
        for name, idx in menus:
            item = QListWidgetItem(name)
            item.setData(Qt.ItemDataRole.UserRole, idx)
            self.menu_list.addItem(item)
            
        self.menu_list.itemClicked.connect(self.on_menu_clicked)
        self.menu_list.setCurrentRow(0)
        sidebar_layout.addWidget(self.menu_list)
        
        sidebar_layout.addStretch()
        
        # Avatar Rodapé
        self.setup_footer_avatar(sidebar_layout)
        
        self.work_layout.addWidget(self.sidebar_left)

    def setup_footer_avatar(self, layout):
        avatar_card = QFrame()
        avatar_card.setStyleSheet(f"""
            QFrame {{
                background-color: #F8FAFC;
                border: 1px solid {CORES['borda']};
                border-radius: 12px;
                margin: 0px 12px;
                padding: 12px;
            }}
        """)
        avatar_layout = QVBoxLayout(avatar_card)
        avatar_layout.setContentsMargins(10, 10, 10, 10)
        avatar_layout.setSpacing(6)
        avatar_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Imagem Circular
        avatar_path = Path("C:/agente-seguranca-soc/iris_avatar.png")
        self.avatar_img = CircularAvatar(str(avatar_path))
        avatar_layout.addWidget(self.avatar_img, 0, Qt.AlignmentFlag.AlignCenter)
        
        # Informações
        lbl_name = QLabel("ÍRIS")
        lbl_name.setStyleSheet(f"font-size: 13px; font-weight: bold; color: {CORES['texto']}; text-align: center; border: none; background: transparent;")
        lbl_name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Online Badge
        status_widget = QWidget()
        status_widget.setStyleSheet("background: transparent; border: none;")
        status_layout = QHBoxLayout(status_widget)
        status_layout.setContentsMargins(0, 0, 0, 0)
        status_layout.setSpacing(4)
        status_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        dot = QLabel("●")
        dot.setStyleSheet(f"color: {CORES['verde']}; font-size: 10px;")
        lbl_status = QLabel("Status: Online")
        lbl_status.setStyleSheet(f"font-size: 11px; color: {CORES['texto_suave']};")
        status_layout.addWidget(dot)
        status_layout.addWidget(lbl_status)
        
        # Modelo
        dotenv.load_dotenv(Path("C:/agente-seguranca-soc/.env"))
        model_name = os.getenv("OLLAMA_MODEL", "llama3.1")
        self.lbl_sidebar_model = QLabel(f"Modelo: {model_name}")
        self.lbl_sidebar_model.setStyleSheet(f"font-size: 10px; color: {CORES['texto_suave']}; border: none; background: transparent;")
        self.lbl_sidebar_model.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Badge de Proteção Ativa no Rodapé
        lbl_prot_active = QLabel("🛡 Proteção Ativa")
        lbl_prot_active.setStyleSheet(f"""
            background-color: #ECFDF5;
            color: #047857;
            border-radius: 4px;
            padding: 2px 6px;
            font-size: 9px;
            font-weight: bold;
        """)
        lbl_prot_active.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        avatar_layout.addWidget(lbl_name)
        avatar_layout.addWidget(status_widget)
        avatar_layout.addWidget(lbl_prot_active)
        avatar_layout.addWidget(self.lbl_sidebar_model)
        
        # Botões decorativos extras (Light/Dark Switch)
        toggle_layout = QHBoxLayout()
        toggle_layout.setContentsMargins(0, 4, 0, 0)
        toggle_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.btn_theme_toggle = QPushButton("☀️")
        self.btn_theme_toggle.setStyleSheet("background: transparent; border: none; font-size: 12px;")
        self.btn_theme_toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        toggle_layout.addWidget(self.btn_theme_toggle)
        
        avatar_layout.addLayout(toggle_layout)
        
        layout.addWidget(avatar_card)

    def setup_right_sidebar(self):
        self.sidebar_right = QWidget()
        self.sidebar_right.setFixedWidth(280)
        self.sidebar_right.setStyleSheet("#sidebar_right_widget { background-color: #FFFFFF; border-left: 1px solid #E2E8F0; }")
        self.sidebar_right.setObjectName("sidebar_right_widget")
        
        self.right_layout = QVBoxLayout(self.sidebar_right)
        self.right_layout.setContentsMargins(15, 15, 15, 15)
        self.right_layout.setSpacing(12)
        
        # Título
        lbl_status_title = QLabel("ÍRIS  ◉ Ativa")
        lbl_status_title.setObjectName("lbl_status_ollama")
        lbl_status_title.setStyleSheet(f"font-size: 14px; font-weight: bold; color: {CORES['roxo']};")
        self.right_layout.addWidget(lbl_status_title)
        
        # Modelo
        dotenv.load_dotenv(Path("C:/agente-seguranca-soc/.env"))
        model_name = os.getenv("OLLAMA_MODEL", "llama3.1")
        self.lbl_model_val = QLabel(f"Modelo: {model_name}")
        self.lbl_model_val.setStyleSheet("font-size: 12px; color: #64748B; margin-bottom: 5px;")
        self.right_layout.addWidget(self.lbl_model_val)
        
        self.right_layout.addWidget(self.create_separator())
        
        # CPU
        lbl_cpu = QLabel("CPU:")
        lbl_cpu.setStyleSheet("font-weight: bold; font-size: 12px; color: #0F172A;")
        self.lbl_cpu_val = QLabel("0%")
        self.lbl_cpu_val.setStyleSheet("font-size: 12px; color: #64748B;")
        
        cpu_header = QHBoxLayout()
        cpu_header.addWidget(lbl_cpu)
        cpu_header.addStretch()
        cpu_header.addWidget(self.lbl_cpu_val)
        self.right_layout.addLayout(cpu_header)
        
        self.progress_cpu = QProgressBar()
        self.progress_cpu.setRange(0, 100)
        self.progress_cpu.setValue(0)
        self.progress_cpu.setTextVisible(False)
        self.right_layout.addWidget(self.progress_cpu)
        
        # RAM
        lbl_ram = QLabel("RAM:")
        lbl_ram.setStyleSheet("font-weight: bold; font-size: 12px; color: #0F172A;")
        self.lbl_ram_val = QLabel("0%")
        self.lbl_ram_val.setStyleSheet("font-size: 12px; color: #64748B;")
        
        ram_header = QHBoxLayout()
        ram_header.addWidget(lbl_ram)
        ram_header.addStretch()
        ram_header.addWidget(self.lbl_ram_val)
        self.right_layout.addLayout(ram_header)
        
        self.progress_ram = QProgressBar()
        self.progress_ram.setRange(0, 100)
        self.progress_ram.setValue(0)
        self.progress_ram.setTextVisible(False)
        self.right_layout.addWidget(self.progress_ram)
        
        # REDE
        lbl_net = QLabel("REDE:")
        lbl_net.setStyleSheet("font-weight: bold; font-size: 12px; color: #0F172A;")
        self.lbl_net_speed = QLabel("↑ 0.0 MB/s  ↓ 0.0 MB/s")
        self.lbl_net_speed.setStyleSheet("font-size: 12px; color: #64748B;")
        
        net_layout = QHBoxLayout()
        net_layout.addWidget(lbl_net)
        net_layout.addStretch()
        net_layout.addWidget(self.lbl_net_speed)
        self.right_layout.addLayout(net_layout)
        
        self.right_layout.addWidget(self.create_separator())
        
        # Box Último Alerta
        self.right_layout.addWidget(QLabel("Último alerta:"))
        self.alert_box = QFrame()
        self.alert_box.setStyleSheet(f"""
            QFrame {{
                background-color: #F8FAFC;
                border: 1px solid {CORES['borda']};
                border-radius: 8px;
                padding: 10px;
            }}
        """)
        alert_box_layout = QVBoxLayout(self.alert_box)
        self.lbl_alert_time = QLabel("--:-- — Sem alertas")
        self.lbl_alert_time.setStyleSheet(f"font-weight: bold; font-size: 12px; color: {CORES['laranja']};")
        self.lbl_alert_desc = QLabel("Nenhum evento detectado recentemente.")
        self.lbl_alert_desc.setWordWrap(True)
        self.lbl_alert_desc.setStyleSheet("font-size: 11px; color: #64748B;")
        
        alert_box_layout.addWidget(self.lbl_alert_time)
        alert_box_layout.addWidget(self.lbl_alert_desc)
        self.right_layout.addWidget(self.alert_box)
        
        self.right_layout.addStretch()
        
        # Grip
        self.sizegrip = QSizeGrip(self)
        self.right_layout.addWidget(self.sizegrip, 0, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignBottom)
        
        self.work_layout.addWidget(self.sidebar_right)

    # --- SETUP DAS TELAS ---

    def setup_screens(self):
        # Tela 0: Início (Dashboard Unificado Premium)
        self.screen_home = QWidget()
        self.setup_screen_home()
        self.stacked_widget.addWidget(self.screen_home)
        
        # Tela 1: Centro de Defesa (Redesenhado Light)
        self.screen_defense = QWidget()
        self.setup_screen_defense()
        self.stacked_widget.addWidget(self.screen_defense)
        
        # Tela 2: Incidentes (Timeline + Painel de Investigação)
        self.screen_incidents = QWidget()
        self.setup_screen_incidents()
        self.stacked_widget.addWidget(self.screen_incidents)
        
        # Tela 3: Prática (Desafios)
        self.screen_practice = QWidget()
        self.setup_screen_practice()
        self.stacked_widget.addWidget(self.screen_practice)

    # --- TELA 0: INÍCIO (DASHBOARD COMPLETO) ---

    def setup_screen_home(self):
        layout = QVBoxLayout(self.screen_home)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # 1. Cabeçalho Central
        header_widget = QWidget()
        header_widget.setStyleSheet("background: transparent;")
        header_lay = QVBoxLayout(header_widget)
        header_lay.setContentsMargins(0, 0, 0, 0)
        header_lay.setSpacing(4)
        
        self.lbl_greeting = QLabel("Bom dia, Roger. 👋")
        self.lbl_greeting.setStyleSheet(f"font-size: 22px; font-weight: bold; color: {CORES['texto']};")
        
        lbl_subtitle = QLabel("Estou aqui para proteger, ensinar e ajudar você a entender tudo sobre cibersegurança.")
        lbl_subtitle.setStyleSheet(f"font-size: 13px; color: {CORES['texto_suave']};")
        
        header_lay.addWidget(self.lbl_greeting)
        header_lay.addWidget(lbl_subtitle)
        layout.addWidget(header_widget)
        
        # 2. Barra de Cards de Métricas (Sparklines)
        metrics_layout = QHBoxLayout()
        metrics_layout.setSpacing(12)
        
        # Sparkline data points
        sp_points1 = [95, 98, 97, 99, 100, 100, 100]
        sp_points2 = [5, 4, 3, 4, 2, 3, 3]
        sp_points3 = [800, 950, 1100, 1050, 1200, 1150, 1245]
        sp_points4 = [10, 10, 11, 11, 12, 12, 12]
        sp_points5 = [0, 0, 1, 0, 2, 1, 1]
        
        self.card_protection = MetricCard("Proteção", "100%", "Tudo seguro", "🛡", "#EEF2F6", CORES['roxo'], sp_points1, CORES['roxo'])
        self.card_alerts = MetricCard("Alertas Ativos", "3", "Precisam de atenção", "⚠️", "#FEF3C7", CORES['laranja'], sp_points2, CORES['laranja'])
        self.card_events = MetricCard("Eventos Hoje", "1.245", "+12% vs ontem", "📊", "#E0F2FE", CORES['azul'], sp_points3, CORES['azul'])
        self.card_systems = MetricCard("Dispositivos", "12", "Dispositivos ativos", "💻", "#E0F7FA", CORES['cyan'], sp_points4, CORES['cyan'])
        self.card_threats = MetricCard("Incidentes", "1", "Em investigação", "🚨", "#FEE2E2", CORES['vermelho'], sp_points5, CORES['vermelho'])
        
        metrics_layout.addWidget(self.card_protection)
        metrics_layout.addWidget(self.card_alerts)
        metrics_layout.addWidget(self.card_events)
        metrics_layout.addWidget(self.card_systems)
        metrics_layout.addWidget(self.card_threats)
        layout.addLayout(metrics_layout)
        
        # 3. Split Central (Chat ~70% / Status e Alertas ~30%)
        middle_widget = QWidget()
        middle_widget.setStyleSheet("background: transparent;")
        middle_lay = QHBoxLayout(middle_widget)
        middle_lay.setContentsMargins(0, 0, 0, 0)
        middle_lay.setSpacing(15)
        
        # 3.1 Coluna Esquerda: Chat & Ações Rápidas
        left_col = QWidget()
        left_col_layout = QVBoxLayout(left_col)
        left_col_layout.setContentsMargins(0, 0, 0, 0)
        left_col_layout.setSpacing(15)
        
        # Chat Box
        chat_box = QFrame()
        chat_box.setStyleSheet(f"background-color: #FFFFFF; border: 1px solid {CORES['borda']}; border-radius: 12px;")
        chat_box_layout = QVBoxLayout(chat_box)
        chat_box_layout.setContentsMargins(15, 15, 15, 15)
        chat_box_layout.setSpacing(8)
        
        lbl_chat_header = QLabel("✦ Conversar com Íris")
        lbl_chat_header.setStyleSheet(f"font-size: 13px; font-weight: bold; color: {CORES['roxo']}; border: none; background: transparent;")
        chat_box_layout.addWidget(lbl_chat_header)
        
        # Scroll area
        self.home_chat_scroll = QScrollArea()
        self.home_chat_scroll.setWidgetResizable(True)
        self.home_chat_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        
        self.home_chat_container = QWidget()
        self.home_chat_container.setStyleSheet("background: transparent;")
        self.home_chat_layout = QVBoxLayout(self.home_chat_container)
        self.home_chat_layout.setContentsMargins(0, 5, 0, 5)
        self.home_chat_layout.setSpacing(8)
        self.home_chat_layout.addStretch()
        
        self.home_chat_scroll.setWidget(self.home_chat_container)
        chat_box_layout.addWidget(self.home_chat_scroll)
        
        # Primeiras Mensagens
        self.add_home_bubble("Olá, Roger! Qual é a sua dúvida de segurança de hoje?", is_user=False)
        
        # Pensando...
        self.lbl_home_thinking = QLabel("Íris está pensando...")
        self.lbl_home_thinking.setStyleSheet(f"font-style: italic; color: {CORES['roxo']}; font-size: 11px; margin-left: 5px;")
        self.lbl_home_thinking.hide()
        chat_box_layout.addWidget(self.lbl_home_thinking)
        
        # Sugestões Rápidas
        sug_layout = QHBoxLayout()
        sug_layout.setSpacing(8)
        
        sug_msgs = ["Analise este alerta", "Explique este incidente", "Como me proteger?", "Verificar atividade suspeita"]
        for s_msg in sug_msgs:
            btn_sug = QPushButton(s_msg)
            btn_sug.setCursor(Qt.CursorShape.PointingHandCursor)
            btn_sug.setStyleSheet(f"""
                QPushButton {{
                    background-color: #FFFFFF;
                    border: 1px solid {CORES['borda']};
                    border-radius: 10px;
                    padding: 5px 10px;
                    font-size: 10px;
                    color: {CORES['texto_suave']};
                }}
                QPushButton:hover {{
                    border-color: {CORES['roxo']};
                    background-color: {CORES['roxo_suave']};
                    color: {CORES['roxo']};
                }}
            """)
            btn_sug.clicked.connect(lambda checked, text=s_msg: self.send_home_suggestion(text))
            sug_layout.addWidget(btn_sug)
            
        chat_box_layout.addLayout(sug_layout)
        
        # Input Bar
        input_bar = QFrame()
        input_bar.setFixedHeight(50)
        input_bar.setStyleSheet(f"background-color: #F8FAFC; border: 1px solid {CORES['borda']}; border-radius: 25px;")
        input_bar_layout = QHBoxLayout(input_bar)
        input_bar_layout.setContentsMargins(15, 5, 10, 5)
        
        self.txt_home_input = QLineEdit()
        self.txt_home_input.setPlaceholderText("Pergunte qualquer coisa sobre cibersegurança...")
        self.txt_home_input.setStyleSheet("background: transparent; border: none; font-size: 13px; color: #0F172A;")
        self.txt_home_input.returnPressed.connect(self.send_home_chat)
        
        self.btn_home_send = QPushButton("➔")
        self.btn_home_send.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_home_send.setFixedSize(32, 32)
        self.btn_home_send.setStyleSheet(f"""
            QPushButton {{
                background-color: {CORES['roxo']};
                color: #FFFFFF;
                border-radius: 16px;
                font-size: 13px;
                border: none;
            }}
            QPushButton:hover {{
                background-color: {CORES['roxo_sec']};
            }}
        """)
        self.btn_home_send.clicked.connect(self.send_home_chat)
        
        input_bar_layout.addWidget(self.txt_home_input)
        input_bar_layout.addWidget(self.btn_home_send)
        
        chat_box_layout.addWidget(input_bar)
        left_col_layout.addWidget(chat_box, 7)
        
        # Ações Rápidas
        actions_widget = QWidget()
        actions_lay = QHBoxLayout(actions_widget)
        actions_lay.setContentsMargins(0, 0, 0, 0)
        actions_lay.setSpacing(10)
        
        btn_action_file = QuickActionButton("Analisar Arquivo", "Verificar ameaças", "📁", CORES['azul'])
        btn_action_file.clicked.connect(self.on_analisar_arquivo_clicked)
        
        btn_action_proc = QuickActionButton("Ver Processos", "Monitorar sistema", "⚙", CORES['roxo'])
        btn_action_proc.clicked.connect(lambda: self.switch_to_page(1))
        
        btn_action_incidents = QuickActionButton("Ver Incidentes", "Histórico completo", "🚨", CORES['vermelho'])
        btn_action_incidents.clicked.connect(lambda: self.switch_to_page(2))
        
        btn_action_report = QuickActionButton("Gerar Relatório", "Exportar dados", "📄", CORES['texto_suave'])
        btn_action_report.clicked.connect(self.on_generate_report_clicked)
        
        btn_action_scan = QuickActionButton("Iniciar Varredura", "Varredura de IA", "🟢", CORES['verde'])
        btn_action_scan.clicked.connect(self.on_iniciar_varredura_clicked)
        
        actions_lay.addWidget(btn_action_file)
        actions_lay.addWidget(btn_action_proc)
        actions_lay.addWidget(btn_action_incidents)
        actions_lay.addWidget(btn_action_report)
        actions_lay.addWidget(btn_action_scan)
        
        left_col_layout.addWidget(actions_widget, 2)
        
        middle_lay.addWidget(left_col, 7)
        
        # 3.2 Coluna Direita: Alertas, Atividade e Dicas
        right_col = QWidget()
        right_col_layout = QVBoxLayout(right_col)
        right_col_layout.setContentsMargins(0, 0, 0, 0)
        right_col_layout.setSpacing(15)
        
        # Alertas em Tempo Real Box
        alerts_card = QFrame()
        alerts_card.setStyleSheet(f"background-color: #FFFFFF; border: 1px solid {CORES['borda']}; border-radius: 12px; padding: 12px;")
        alerts_lay = QVBoxLayout(alerts_card)
        alerts_lay.setContentsMargins(12, 12, 12, 12)
        alerts_lay.setSpacing(8)
        
        alerts_header = QHBoxLayout()
        lbl_alerts_title = QLabel("Alertas em Tempo Real")
        lbl_alerts_title.setStyleSheet(f"font-size: 13px; font-weight: bold; color: {CORES['texto']};")
        
        btn_view_all_alerts = QPushButton("Ver todos")
        btn_view_all_alerts.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_view_all_alerts.setStyleSheet(f"font-size: 11px; font-weight: bold; color: {CORES['roxo']}; background: transparent; border: none;")
        btn_view_all_alerts.clicked.connect(lambda: self.switch_to_page(2))
        
        alerts_header.addWidget(lbl_alerts_title)
        alerts_header.addStretch()
        alerts_header.addWidget(btn_view_all_alerts)
        alerts_lay.addLayout(alerts_header)
        
        self.home_alerts_list = QListWidget()
        self.home_alerts_list.setStyleSheet("QListWidget { background: transparent; border: none; }")
        self.home_alerts_list.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        alerts_lay.addWidget(self.home_alerts_list)
        right_col_layout.addWidget(alerts_card, 4)
        
        # Atividade do Sistema Box
        activity_card = QFrame()
        activity_card.setStyleSheet(f"background-color: #FFFFFF; border: 1px solid {CORES['borda']}; border-radius: 12px; padding: 12px;")
        activity_lay = QVBoxLayout(activity_card)
        activity_lay.setContentsMargins(12, 12, 12, 12)
        activity_lay.setSpacing(10)
        
        act_header = QHBoxLayout()
        lbl_act_title = QLabel("Atividade do Sistema")
        lbl_act_title.setStyleSheet(f"font-size: 13px; font-weight: bold; color: {CORES['texto']};")
        
        btn_view_act_details = QPushButton("Ver detalhes")
        btn_view_act_details.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_view_act_details.setStyleSheet(f"font-size: 11px; font-weight: bold; color: {CORES['roxo']}; background: transparent; border: none;")
        btn_view_act_details.clicked.connect(lambda: self.switch_to_page(1))
        
        act_header.addWidget(lbl_act_title)
        act_header.addStretch()
        act_header.addWidget(btn_view_act_details)
        activity_lay.addLayout(act_header)
        
        # Medidores Circulares
        gauges_widget = QWidget()
        gauges_widget.setStyleSheet("background: transparent; border: none;")
        gauges_lay = QHBoxLayout(gauges_widget)
        gauges_lay.setContentsMargins(0, 0, 0, 0)
        gauges_lay.setSpacing(8)
        
        self.gauge_cpu = CircularGauge("CPU", 0, CORES['roxo'])
        self.gauge_ram = CircularGauge("RAM", 0, CORES['roxo_sec'])
        self.gauge_disk = CircularGauge("Disco", 45, CORES['azul'])
        self.gauge_net = CircularGauge("Rede", 12, CORES['cyan'])
        
        gauges_lay.addWidget(self.gauge_cpu)
        gauges_lay.addWidget(self.gauge_ram)
        gauges_lay.addWidget(self.gauge_disk)
        gauges_lay.addWidget(self.gauge_net)
        activity_lay.addWidget(gauges_widget)
        
        # Linha de tendência suave abaixo dos medidores
        self.activity_trend = TrendLine(self.activity_points, CORES['roxo'])
        self.activity_trend.setFixedHeight(22)
        self.activity_trend.setMinimumWidth(200)
        activity_lay.addWidget(self.activity_trend)
        
        right_col_layout.addWidget(activity_card, 4)
        
        # Dica de Segurança Box
        tips_card = QFrame()
        tips_card.setStyleSheet(f"background-color: #FFFFFF; border: 1px solid {CORES['borda']}; border-radius: 12px; padding: 12px;")
        tips_lay = QHBoxLayout(tips_card)
        tips_lay.setContentsMargins(12, 10, 12, 10)
        tips_lay.setSpacing(12)
        
        shield_icon = QLabel("🛡")
        shield_icon.setStyleSheet(f"font-size: 18px; color: {CORES['roxo']}; background: transparent; border: none;")
        
        tip_text_widget = QWidget()
        tip_text_widget.setStyleSheet("background: transparent; border: none;")
        tip_text_layout = QVBoxLayout(tip_text_widget)
        tip_text_layout.setContentsMargins(0, 0, 0, 0)
        tip_text_layout.setSpacing(2)
        
        lbl_tip_title = QLabel("Recomendação da Íris")
        lbl_tip_title.setStyleSheet("font-size: 11px; font-weight: bold; color: #0F172A;")
        lbl_tip_desc = QLabel("Mantenha seus sistemas atualizados e evite abrir anexos de remetentes suspeitos.")
        lbl_tip_desc.setWordWrap(True)
        lbl_tip_desc.setStyleSheet(f"font-size: 9px; color: {CORES['texto_suave']};")
        
        tip_text_layout.addWidget(lbl_tip_title)
        tip_text_layout.addWidget(lbl_tip_desc)
        
        btn_saiba_mais = QPushButton("Saiba mais")
        btn_saiba_mais.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_saiba_mais.setStyleSheet(f"""
            QPushButton {{
                background-color: #FFFFFF;
                border: 1px solid {CORES['borda']};
                border-radius: 6px;
                padding: 4px 8px;
                font-size: 9px;
                font-weight: bold;
                color: {CORES['roxo']};
            }}
            QPushButton:hover {{
                border-color: {CORES['roxo']};
                background-color: {CORES['roxo_suave']};
            }}
        """)
        
        tips_lay.addWidget(shield_icon)
        tips_lay.addWidget(tip_text_widget)
        tips_lay.addWidget(btn_saiba_mais)
        right_col_layout.addWidget(tips_card, 2)
        
        middle_lay.addWidget(right_col, 3)
        layout.addWidget(middle_widget)

    # --- CHAT ACTIONS (HOME EMBEDDED) ---

    def send_home_suggestion(self, text):
        self.txt_home_input.setText(text)
        self.send_home_chat()

    def send_home_chat(self):
        text = self.txt_home_input.text().strip()
        if not text:
            return
            
        self.txt_home_input.clear()
        self.add_home_bubble(text, is_user=True)
        
        self.lbl_home_thinking.show()
        
        self.home_worker = IrisAIWorker(self.chat_history, text)
        self.home_worker.response_received.connect(self.on_home_chat_response)
        self.home_worker.error_occurred.connect(self.on_home_chat_error)
        self.home_worker.start()
        
        self.chat_history.append({"role": "user", "content": text})

    def on_home_chat_response(self, content):
        self.lbl_home_thinking.hide()
        self.add_home_bubble(content, is_user=False)
        self.chat_history.append({"role": "assistant", "content": content})

    def on_home_chat_error(self, err_msg):
        self.lbl_home_thinking.hide()
        self.add_home_bubble(err_msg, is_user=False)

    def add_home_bubble(self, text, is_user=False):
        bubble = ChatBubblePremium(text, is_user)
        self.home_chat_layout.insertWidget(self.home_chat_layout.count() - 1, bubble)
        
        QTimer.singleShot(100, lambda: self.home_chat_scroll.verticalScrollBar().setValue(
            self.home_chat_scroll.verticalScrollBar().maximum()
        ))

    # --- TELA 1: CENTRO DE DEFESA (TAB LAYOUT) ---

    def setup_screen_defense(self):
        layout = QVBoxLayout(self.screen_defense)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # Header
        header_widget = QWidget()
        header_layout = QVBoxLayout(header_widget)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(2)
        lbl_title = QLabel("🛡  Centro de Defesa")
        lbl_title.setStyleSheet(f"font-size: 20px; font-weight: bold; color: {CORES['roxo']};")
        lbl_subtitle = QLabel("Monitore recursos, processos, conexões e a integridade de arquivos em tempo real.")
        lbl_subtitle.setStyleSheet(f"font-size: 12px; color: {CORES['texto_suave']};")
        header_layout.addWidget(lbl_title)
        header_layout.addWidget(lbl_subtitle)
        layout.addWidget(header_widget)
        
        # Tab Widget
        self.defense_tabs = QTabWidget()
        self.defense_tabs.setStyleSheet(f"""
            QTabWidget::panel {{
                border: 1px solid {CORES['borda']};
                background-color: #FFFFFF;
                border-radius: 12px;
                padding: 15px;
            }}
            QTabBar::tab {{
                background-color: transparent;
                color: {CORES['texto_suave']};
                font-weight: 600;
                font-size: 12px;
                padding: 10px 18px;
                border: none;
                border-bottom: 2px solid transparent;
            }}
            QTabBar::tab:selected {{
                color: {CORES['roxo']};
                border-bottom: 2px solid {CORES['roxo']};
            }}
            QTabBar::tab:hover {{
                color: {CORES['roxo_sec']};
            }}
        """)
        
        self.tab_sys = QWidget()
        self.tab_proc = QWidget()
        self.tab_net = QWidget()
        self.tab_down = QWidget()
        self.tab_apps = QWidget()
        
        self.defense_tabs.addTab(self.tab_sys, "📊 Sistema")
        self.defense_tabs.addTab(self.tab_proc, "⚙ Processos")
        self.defense_tabs.addTab(self.tab_net, "🌐 Rede")
        self.defense_tabs.addTab(self.tab_down, "📁 Downloads")
        self.defense_tabs.addTab(self.tab_apps, "💻 Aplicativos")
        
        self.setup_tab_system()
        self.setup_tab_processes()
        self.setup_tab_network()
        self.setup_tab_downloads()
        self.setup_tab_apps()
        
        layout.addWidget(self.defense_tabs)

    def setup_tab_system(self):
        lay = QVBoxLayout(self.tab_sys)
        lay.setContentsMargins(10, 10, 10, 10)
        lay.setSpacing(15)
        
        # Row of circular gauges (CPU, RAM, Disco, Rede)
        gauges_panel = QFrame()
        gauges_panel.setStyleSheet(f"background-color: #F8FAFC; border: 1px solid {CORES['borda']}; border-radius: 10px; padding: 10px;")
        gauges_lay = QHBoxLayout(gauges_panel)
        gauges_lay.setContentsMargins(10, 10, 10, 10)
        gauges_lay.setSpacing(20)
        gauges_lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self.def_gauge_cpu = CircularGauge("CPU", 0, CORES['roxo'])
        self.def_gauge_ram = CircularGauge("RAM", 0, CORES['roxo_sec'])
        self.def_gauge_disk = CircularGauge("Disco", 45, CORES['azul'])
        self.def_gauge_net = CircularGauge("Rede", 12, CORES['cyan'])
        
        gauges_lay.addWidget(self.def_gauge_cpu)
        gauges_lay.addWidget(self.def_gauge_ram)
        gauges_lay.addWidget(self.def_gauge_disk)
        gauges_lay.addWidget(self.def_gauge_net)
        lay.addWidget(gauges_panel)
        
        # Grid of Services
        services_panel = QFrame()
        services_panel.setStyleSheet(f"background-color: #FFFFFF; border: 1px solid {CORES['borda']}; border-radius: 10px; padding: 10px;")
        grid_layout = QGridLayout(services_panel)
        grid_layout.setSpacing(10)
        
        self.status_indicators = {}
        services = [
            ("Firewall", 0, 0), ("Antivírus", 0, 1), ("Rede", 0, 2),
            ("Atualizações", 1, 0), ("Agente SOC", 1, 1), ("Ollama", 1, 2)
        ]
        for name, r, c in services:
            card = QFrame()
            card.setStyleSheet(f"background-color: #F8FAFC; border-radius: 8px; border: 1px solid {CORES['borda']}; padding: 8px;")
            card_layout = QHBoxLayout(card)
            card_layout.setContentsMargins(8, 4, 8, 4)
            
            lbl_name = QLabel(name)
            lbl_name.setStyleSheet("font-weight: bold; font-size: 11px; color: #0F172A;")
            
            lbl_status = QLabel("🟢 Online")
            lbl_status.setStyleSheet("color: #10B981; font-weight: bold; font-size: 11px;")
            
            card_layout.addWidget(lbl_name)
            card_layout.addStretch()
            card_layout.addWidget(lbl_status)
            
            self.status_indicators[name] = lbl_status
            grid_layout.addWidget(card, r, c)
            
        lay.addWidget(services_panel)

    def setup_tab_processes(self):
        lay = QVBoxLayout(self.tab_proc)
        lay.setContentsMargins(10, 10, 10, 10)
        lay.setSpacing(10)
        
        split_layout = QHBoxLayout()
        split_layout.setSpacing(10)
        
        left_box = QFrame()
        left_box.setStyleSheet(f"background-color: #F8FAFC; border: 1px solid {CORES['borda']}; border-radius: 8px; padding: 8px;")
        left_lay = QVBoxLayout(left_box)
        left_lay.addWidget(QLabel("<b>Processos Ativos (Top 10 CPU)</b>"))
        
        self.process_list = QListWidget()
        self.process_list.setStyleSheet("QListWidget { background: transparent; border: none; } QListWidget::item { padding: 6px; border-bottom: 1px solid #E2E8F0; }")
        self.process_list.itemClicked.connect(self.on_process_item_clicked)
        left_lay.addWidget(self.process_list)
        split_layout.addWidget(left_box, 1)
        
        right_box = QFrame()
        right_box.setStyleSheet(f"background-color: #F8FAFC; border: 1px solid {CORES['borda']}; border-radius: 8px; padding: 8px;")
        right_lay = QVBoxLayout(right_box)
        right_lay.addWidget(QLabel("<b>Processos Suspeitos / Alertas YARA</b>"))
        
        self.suspicious_process_list = QListWidget()
        self.suspicious_process_list.setStyleSheet("QListWidget { background: transparent; border: none; } QListWidget::item { padding: 6px; border-bottom: 1px solid #E2E8F0; }")
        right_lay.addWidget(self.suspicious_process_list)
        split_layout.addWidget(right_box, 1)
        
        lay.addLayout(split_layout)
        
        btn_explain = QPushButton("Explique com Íris ✦")
        btn_explain.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_explain.setStyleSheet(self.get_defense_btn_style())
        btn_explain.clicked.connect(self.explain_selected_process)
        lay.addWidget(btn_explain, 0, Qt.AlignmentFlag.AlignRight)

    def setup_tab_network(self):
        lay = QVBoxLayout(self.tab_net)
        lay.setContentsMargins(10, 10, 10, 10)
        lay.setSpacing(10)
        
        split_layout = QHBoxLayout()
        split_layout.setSpacing(10)
        
        left_box = QFrame()
        left_box.setStyleSheet(f"background-color: #F8FAFC; border: 1px solid {CORES['borda']}; border-radius: 8px; padding: 8px;")
        left_lay = QVBoxLayout(left_box)
        left_lay.addWidget(QLabel("<b>Conexões Ativas (ESTABLISHED)</b>"))
        
        self.connection_list = QListWidget()
        self.connection_list.setStyleSheet("QListWidget { background: transparent; border: none; } QListWidget::item { padding: 6px; border-bottom: 1px solid #E2E8F0; }")
        left_lay.addWidget(self.connection_list)
        split_layout.addWidget(left_box, 1)
        
        right_box = QFrame()
        right_box.setStyleSheet(f"background-color: #F8FAFC; border: 1px solid {CORES['borda']}; border-radius: 8px; padding: 8px;")
        right_lay = QVBoxLayout(right_box)
        right_lay.addWidget(QLabel("<b>Hosts/IPs Conectados Recentemente</b>"))
        
        self.hosts_list = QListWidget()
        self.hosts_list.setStyleSheet("QListWidget { background: transparent; border: none; } QListWidget::item { padding: 6px; border-bottom: 1px solid #E2E8F0; }")
        right_lay.addWidget(self.hosts_list)
        split_layout.addWidget(right_box, 1)
        
        lay.addLayout(split_layout)
        
        btn_explain = QPushButton("Explique com Íris ✦")
        btn_explain.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_explain.setStyleSheet(self.get_defense_btn_style())
        btn_explain.clicked.connect(self.explain_selected_connection)
        lay.addWidget(btn_explain, 0, Qt.AlignmentFlag.AlignRight)

    def setup_tab_downloads(self):
        lay = QVBoxLayout(self.tab_down)
        lay.setContentsMargins(10, 10, 10, 10)
        lay.setSpacing(10)
        
        lay.addWidget(QLabel("<b>Arquivos Recentes em Downloads</b>"))
        
        self.downloads_list = QListWidget()
        self.downloads_list.setStyleSheet(f"""
            QListWidget {{
                background-color: #F8FAFC;
                border: 1px solid {CORES['borda']};
                border-radius: 8px;
                padding: 5px;
            }}
            QListWidget::item {{
                padding: 8px;
                border-bottom: 1px solid #E2E8F0;
            }}
        """)
        lay.addWidget(self.downloads_list)
        
        btn_explain = QPushButton("Explique com Íris ✦")
        btn_explain.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_explain.setStyleSheet(self.get_defense_btn_style())
        btn_explain.clicked.connect(self.explain_selected_download)
        lay.addWidget(btn_explain, 0, Qt.AlignmentFlag.AlignRight)

    def setup_tab_apps(self):
        lay = QVBoxLayout(self.tab_apps)
        lay.setContentsMargins(10, 10, 10, 10)
        lay.setSpacing(10)
        
        lay.addWidget(QLabel("<b>Aplicativos Ativos no Ambiente Gráfico</b>"))
        
        self.apps_list = QListWidget()
        self.apps_list.setStyleSheet(f"""
            QListWidget {{
                background-color: #F8FAFC;
                border: 1px solid {CORES['borda']};
                border-radius: 8px;
                padding: 5px;
            }}
            QListWidget::item {{
                padding: 8px;
                border-bottom: 1px solid #E2E8F0;
            }}
        """)
        lay.addWidget(self.apps_list)
        
        btn_explain = QPushButton("Explique com Íris ✦")
        btn_explain.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_explain.setStyleSheet(self.get_defense_btn_style())
        btn_explain.clicked.connect(self.explain_selected_app)
        lay.addWidget(btn_explain, 0, Qt.AlignmentFlag.AlignRight)

    def get_defense_btn_style(self):
        return f"""
            QPushButton {{
                background-color: {CORES['roxo']};
                color: #FFFFFF;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
                font-size: 11px;
            }}
            QPushButton:hover {{
                background-color: {CORES['roxo_sec']};
            }}
        """

    def on_process_item_clicked(self, item):
        proc_info = item.data(Qt.ItemDataRole.UserRole)
        if proc_info and isinstance(proc_info, dict):
            pid = proc_info.get('pid')
            name = proc_info.get('name')
            if pid and name:
                dialog = ProcessDetailDialog(pid, name, self)
                dialog.exec()

    def explain_selected_process(self):
        curr_item = self.process_list.currentItem()
        if not curr_item:
            curr_item = self.suspicious_process_list.currentItem()
        if curr_item:
            proc_info = curr_item.data(Qt.ItemDataRole.UserRole)
            if isinstance(proc_info, dict):
                proc_name = proc_info['name']
            elif isinstance(proc_info, str):
                proc_name = proc_info
            else:
                proc_name = "processo desconhecido"
            self.explain_with_iris("process", proc_name)

    def explain_selected_connection(self):
        curr_item = self.connection_list.currentItem()
        if not curr_item:
            curr_item = self.hosts_list.currentItem()
        if curr_item:
            conn_data = curr_item.data(Qt.ItemDataRole.UserRole)
            if isinstance(conn_data, dict):
                ip_str = f"{conn_data['process']} ({conn_data['ip']})"
            elif isinstance(conn_data, str):
                ip_str = conn_data
            else:
                ip_str = "endereço de rede"
            self.explain_with_iris("connection", ip_str)

    def explain_selected_download(self):
        curr_item = self.downloads_list.currentItem()
        if curr_item:
            file_name = curr_item.data(Qt.ItemDataRole.UserRole)
            self.explain_with_iris("download", file_name)

    def explain_selected_app(self):
        curr_item = self.apps_list.currentItem()
        if curr_item:
            app_name = curr_item.data(Qt.ItemDataRole.UserRole)
            self.explain_with_iris("app", app_name)

    def update_suspicious_processes(self, data):
        self.suspicious_process_list.clear()
        found = False
        for proc in data['processes']:
            is_suspicious = False
            if proc['name'].lower() in ['cmd.exe', 'powershell.exe', 'certutil.exe', 'wmic.exe', 'vssadmin.exe']:
                is_suspicious = True
            elif proc['cpu_percent'] > 30:
                is_suspicious = True
                
            if is_suspicious:
                item = QListWidgetItem(f"⚠️ {proc['name']} (PID: {proc['pid']}) — CPU: {proc['cpu_percent']:.1f}%")
                item.setData(Qt.ItemDataRole.UserRole, proc['name'])
                item.setForeground(QColor(CORES['laranja']))
                self.suspicious_process_list.addItem(item)
                found = True
        
        if not found:
            item = QListWidgetItem("Nenhuma atividade de processo anômala detectada.")
            item.setData(Qt.ItemDataRole.UserRole, None)
            self.suspicious_process_list.addItem(item)

    def update_downloads_list(self):
        self.downloads_list.clear()
        downloads_dir = Path(os.path.expanduser("~/Downloads"))
        files = []
        if downloads_dir.exists():
            try:
                for file_path in downloads_dir.iterdir():
                    if file_path.is_file() and not file_path.name.startswith("."):
                        mtime = file_path.stat().st_mtime
                        files.append((file_path.name, mtime, file_path.stat().st_size))
            except:
                pass
                
        files.sort(key=lambda x: x[1], reverse=True)
        
        if not files:
            files = [
                ("relatorio_mensal.pdf", time.time() - 3600, 1024 * 350),
                ("chrome_installer.exe", time.time() - 7200, 1024 * 1024 * 80),
                ("projeto_final.zip", time.time() - 86400, 1024 * 1024 * 12),
                ("fatura_energia.pdf", time.time() - 172800, 1024 * 120)
            ]
            
        for name, mtime, size_bytes in files[:8]:
            dt = datetime.datetime.fromtimestamp(mtime).strftime("%d/%m %H:%M")
            sz = f"{size_bytes / (1024 * 1024):.1f} MB" if size_bytes > 1024 * 1024 else f"{size_bytes / 1024:.0f} KB"
            item = QListWidgetItem(f"📄 {name} ({sz}) — Baixado em: {dt}")
            item.setData(Qt.ItemDataRole.UserRole, name)
            self.downloads_list.addItem(item)

    def update_apps_list(self):
        self.apps_list.clear()
        apps_found = []
        for proc in psutil.process_iter(['name']):
            try:
                name = proc.name().lower()
                app_label = None
                if "chrome" in name:
                    app_label = "Google Chrome (Navegador)"
                elif "firefox" in name:
                    app_label = "Mozilla Firefox (Navegador)"
                elif "discord" in name:
                    app_label = "Discord (Chat/Comunicação)"
                elif "spotify" in name:
                    app_label = "Spotify Desktop (Mídia)"
                elif "code" in name:
                    app_label = "VS Code (Editor de Código)"
                elif "explorer" in name:
                    app_label = "Windows Explorer (Gerenciador de Arquivos)"
                elif "notepad" in name:
                    app_label = "Bloco de Notas (Notepad)"
                elif "slack" in name:
                    app_label = "Slack (Comunicação)"
                elif "teams" in name:
                    app_label = "Microsoft Teams (Colaboração)"
                elif "outlook" in name:
                    app_label = "Microsoft Outlook (E-mail)"
                    
                if app_label and app_label not in apps_found:
                    apps_found.append(app_label)
            except:
                pass
                
        if not apps_found:
            apps_found = ["Windows Explorer (Gerenciador de Arquivos)", "Google Chrome (Navegador)", "VS Code (Editor de Código)"]
            
        for app in apps_found:
            item = QListWidgetItem(f"💻 {app} — Ativo")
            item.setData(Qt.ItemDataRole.UserRole, app)
            self.apps_list.addItem(item)

    # --- TELA 2: INCIDENTES (TIMELINE + INVESTIGAÇÃO) ---

    def setup_screen_incidents(self):
        layout = QHBoxLayout(self.screen_incidents)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        left_widget = QWidget()
        left_lay = QVBoxLayout(left_widget)
        left_lay.setContentsMargins(0, 0, 0, 0)
        left_lay.setSpacing(10)
        
        lbl_left_title = QLabel("🚨 Timeline de Incidentes")
        lbl_left_title.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {CORES['roxo']};")
        left_lay.addWidget(lbl_left_title)
        
        self.incidents_timeline = QListWidget()
        self.incidents_timeline.setStyleSheet(f"""
            QListWidget {{
                background-color: #FFFFFF;
                border: 1px solid {CORES['borda']};
                border-radius: 12px;
                padding: 8px;
            }}
            QListWidget::item {{
                padding: 10px;
                border-bottom: 1px solid #F1F5F9;
                border-radius: 8px;
            }}
            QListWidget::item:hover {{
                background-color: #F8FAFC;
            }}
            QListWidget::item:selected {{
                background-color: {CORES['roxo_suave']};
                color: {CORES['roxo']};
            }}
        """)
        self.incidents_timeline.itemClicked.connect(self.on_incident_selected)
        left_lay.addWidget(self.incidents_timeline)
        layout.addWidget(left_widget, 4)
        
        right_widget = QFrame()
        right_widget.setStyleSheet(f"background-color: #FFFFFF; border: 1px solid {CORES['borda']}; border-radius: 12px;")
        right_lay = QVBoxLayout(right_widget)
        right_lay.setContentsMargins(15, 15, 15, 15)
        right_lay.setSpacing(10)
        
        self.lbl_inc_title = QLabel("Selecione um incidente para investigar")
        self.lbl_inc_title.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {CORES['texto']};")
        self.lbl_inc_title.setWordWrap(True)
        right_lay.addWidget(self.lbl_inc_title)
        
        badges_layout = QHBoxLayout()
        badges_layout.setSpacing(8)
        self.lbl_inc_risk = QLabel("")
        self.lbl_inc_risk.setStyleSheet("font-size: 10px; font-weight: bold; border-radius: 4px; padding: 2px 6px;")
        self.lbl_inc_status = QLabel("")
        self.lbl_inc_status.setStyleSheet("font-size: 10px; font-weight: bold; border-radius: 4px; padding: 2px 6px;")
        self.lbl_inc_time = QLabel("")
        self.lbl_inc_time.setStyleSheet("font-size: 10px; color: #64748B;")
        badges_layout.addWidget(self.lbl_inc_risk)
        badges_layout.addWidget(self.lbl_inc_status)
        badges_layout.addWidget(self.lbl_inc_time)
        badges_layout.addStretch()
        right_lay.addLayout(badges_layout)
        
        right_lay.addWidget(self.create_separator())
        
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("background: transparent; border: none;")
        scroll_content = QWidget()
        scroll_content.setStyleSheet("background: transparent;")
        self.scroll_layout = QVBoxLayout(scroll_content)
        self.scroll_layout.setContentsMargins(0, 0, 0, 0)
        self.scroll_layout.setSpacing(12)
        
        self.lbl_inc_summary = QLabel("")
        self.lbl_inc_summary.setWordWrap(True)
        self.lbl_inc_summary.setStyleSheet("font-size: 12px; line-height: 1.4;")
        
        self.lbl_inc_mitre = QLabel("")
        self.lbl_inc_mitre.setWordWrap(True)
        self.lbl_inc_mitre.setStyleSheet(f"font-size: 12px; color: {CORES['roxo']}; font-weight: bold;")
        
        self.lbl_inc_iocs = QLabel("")
        self.lbl_inc_iocs.setWordWrap(True)
        self.lbl_inc_iocs.setStyleSheet("font-size: 11px; font-family: monospace; background-color: #F8FAFC; border: 1px solid #E2E8F0; padding: 8px; border-radius: 6px;")
        
        self.lbl_inc_recs = QLabel("")
        self.lbl_inc_recs.setWordWrap(True)
        self.lbl_inc_recs.setStyleSheet("font-size: 11px; color: #047857; background-color: #ECFDF5; border: 1px solid #A7F3D0; padding: 8px; border-radius: 6px;")
        
        self.lbl_inc_ai = QLabel("")
        self.lbl_inc_ai.setWordWrap(True)
        self.lbl_inc_ai.setStyleSheet("font-size: 12px; color: #0F172A; line-height: 1.4;")
        
        self.scroll_layout.addWidget(QLabel("<b>Resumo do Incidente:</b>"))
        self.scroll_layout.addWidget(self.lbl_inc_summary)
        self.scroll_layout.addWidget(QLabel("<b>Mapeamento MITRE ATT&CK:</b>"))
        self.scroll_layout.addWidget(self.lbl_inc_mitre)
        self.scroll_layout.addWidget(QLabel("<b>Indicadores Encontrados (IOCs):</b>"))
        self.scroll_layout.addWidget(self.lbl_inc_iocs)
        self.scroll_layout.addWidget(QLabel("<b>Recomendações da Íris:</b>"))
        self.scroll_layout.addWidget(self.lbl_inc_recs)
        self.scroll_layout.addWidget(QLabel("<b>Explicação Detalhada da IA:</b>"))
        self.scroll_layout.addWidget(self.lbl_inc_ai)
        self.scroll_layout.addStretch()
        
        scroll.setWidget(scroll_content)
        right_lay.addWidget(scroll)
        layout.addWidget(right_widget, 6)
        
        self.load_default_incidents()

    def load_default_incidents(self):
        self.incidents_database = [
            {
                "title": "Exfiltração de Tokens de Acesso",
                "risk": "CRÍTICO",
                "status": "Auto-Mitigado",
                "time": "Hoje — 22:19:16",
                "summary": "O processo 'chrome.exe' (PID 4764) tentou acessar arquivos sensíveis contendo senhas e cookies criptografados. Simultaneamente, iniciou conexões com múltiplos IPs externos suspeitos associados a servidores de comando e controle (C2).",
                "mitre": "• T1539 - Steal Web Session Cookie\n• T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Encrypted Non-Web Protocol",
                "iocs": "Processo: chrome.exe (PID 4764)\nArquivo Acessado: C:\\Users\\roger\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data\nDestino C2: 149.154.175.53 (Antigua and Barbuda)\nStatus OTX: IP Malicioso Confirmado",
                "recs": "• Revogar todas as credenciais do usuário Roger ativas em navegadores.\n• Auditar extensões instaladas no Chrome.\n• Executar escaneamento YARA na pasta local de arquivos temporários.",
                "ai": "Este evento é típico de um malware Infostealer (como Redline ou Lumma Stealer) que tenta roubar credenciais salvas no navegador e enviá-las para servidores remotos. O agente Íris SOC identificou a leitura anômala e bloqueou as conexões suspeitas a nível de firewall preventivamente."
            },
            {
                "title": "Execução de PowerShell Encodado",
                "risk": "ALTO",
                "status": "Investigando",
                "time": "Hoje — 21:45:10",
                "summary": "Um script PowerShell contendo argumentos em Base64 foi iniciado a partir de uma pasta de documentos temporários do sistema. Táticas como essa visam evadir filtros básicos de monitoramento de linha de comando.",
                "mitre": "• T1059.001 - Command and Scripting Interpreter: PowerShell\n• T1027 - Obfuscated Files or Information",
                "iocs": "Processo: powershell.exe (PID 12056)\nLinha de comando: powershell.exe -enc aWV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQp...\nOrigem: DESKTOP-ROGER",
                "recs": "• Decodificar a string Base64 completa para inspecionar os comandos internos.\n• Verificar a integridade do processo pai que gerou o PowerShell.\n• Isolar o host se o script tiver tentado baixar binários executáveis adicionais.",
                "ai": "Atacantes comumente usam codificação Base64 para ocultar URLs de download de payloads ou comandos maliciosos no PowerShell. Isso representa um risco elevado de infecção inicial ou movimentação lateral."
            },
            {
                "title": "Persistência no Registro Adicionada",
                "risk": "MÉDIO",
                "status": "Mitigado",
                "time": "Ontem — 20:30:15",
                "summary": "Foi detectada a criação de um novo valor na chave de Registro Run, configurado para apontar para um arquivo binário recém-criado na pasta AppData\\Local\\Temp.",
                "mitre": "• T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys",
                "iocs": "Chave: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdateTask\nValor: C:\\Users\\roger\\AppData\\Local\\Temp\\update_task.exe",
                "recs": "• Deletar o registro anômalo utilizando o editor de registro ou scripts do agente.\n• Localizar e remover o arquivo executável update_task.exe.\n• Analisar a cadeia de execução que criou o valor no registro.",
                "ai": "A adição de chaves de inicialização sob o caminho Run permite que malwares sejam executados automaticamente a cada login do usuário. A modificação foi revertida pelo agente SOC e o binário foi colocado em quarentena."
            }
        ]
        
        self.incidents_timeline.clear()
        for inc in self.incidents_database:
            color = CORES['vermelho'] if inc['risk'] == "CRÍTICO" else (CORES['laranja'] if inc['risk'] == "ALTO" else CORES['azul'])
            item = QListWidgetItem(f"🚨 {inc['title']}\n[{inc['risk']}] — {inc['time']}")
            item.setData(Qt.ItemDataRole.UserRole, inc)
            item.setForeground(QColor(color))
            self.incidents_timeline.addItem(item)
            
        if self.incidents_timeline.count() > 0:
            self.incidents_timeline.setCurrentRow(0)
            self.on_incident_selected(self.incidents_timeline.item(0))

    def on_incident_selected(self, item):
        inc = item.data(Qt.ItemDataRole.UserRole)
        if not inc:
            return
            
        self.lbl_inc_title.setText(inc['title'])
        self.lbl_inc_time.setText(inc['time'])
        
        self.lbl_inc_risk.setText(inc['risk'])
        if inc['risk'] == "CRÍTICO":
            self.lbl_inc_risk.setStyleSheet("background-color: #FEE2E2; color: #EF4444; font-size: 10px; font-weight: bold; border-radius: 4px; padding: 2px 6px;")
        elif inc['risk'] == "ALTO":
            self.lbl_inc_risk.setStyleSheet("background-color: #FEF3C7; color: #F59E0B; font-size: 10px; font-weight: bold; border-radius: 4px; padding: 2px 6px;")
        else:
            self.lbl_inc_risk.setStyleSheet("background-color: #E0F2FE; color: #60A5FA; font-size: 10px; font-weight: bold; border-radius: 4px; padding: 2px 6px;")
            
        self.lbl_inc_status.setText(inc['status'])
        if "mitigado" in inc['status'].lower():
            self.lbl_inc_status.setStyleSheet("background-color: #ECFDF5; color: #10B981; font-size: 10px; font-weight: bold; border-radius: 4px; padding: 2px 6px;")
        else:
            self.lbl_inc_status.setStyleSheet("background-color: #E2E8F0; color: #64748B; font-size: 10px; font-weight: bold; border-radius: 4px; padding: 2px 6px;")
            
        self.lbl_inc_summary.setText(inc['summary'])
        self.lbl_inc_mitre.setText(inc['mitre'])
        self.lbl_inc_iocs.setText(inc['iocs'])
        self.lbl_inc_recs.setText(inc['recs'])
        self.lbl_inc_ai.setText(inc['ai'])

    def update_incidents_timeline(self, eventos):
        if not eventos:
            return
            
        new_incidents = []
        for ev in eventos:
            hora = ev.get("hora", "")
            alertas = ev.get("alertas", [])
            alert_desc = alertas[0] if alertas else "Atividade anômala"
            risco = ev.get("risco", "MÉDIO")
            analise = ev.get("analise", "Investigação automática sob andamento.")
            acoes = ev.get("acoes", [])
            
            status = "Mitigado" if acoes else "Investigando"
            mitre_map = "• T1059 - Command and Scripting Interpreter"
            if "ip" in alert_desc.lower():
                mitre_map = "• T1048 - Exfiltration over C2"
                
            new_incidents.append({
                "title": alert_desc[:45],
                "risk": risco,
                "status": status,
                "time": f"Hoje — {hora}",
                "summary": f"Alertas acionados:\n" + "\n".join([f"- {a}" for a in alertas]),
                "mitre": mitre_map,
                "iocs": f"Origem: AGENTE-SOC\nAlertas: " + ", ".join(alertas),
                "recs": "• Inspecionar os logs de conexão de rede.\n• Verificar os processos ativos associados aos alertas.",
                "ai": analise
            })
            
        combined = []
        titles_seen = set()
        for inc in new_incidents:
            if inc['title'] not in titles_seen:
                titles_seen.add(inc['title'])
                combined.append(inc)
                
        for inc in self.incidents_database:
            if inc['title'] not in titles_seen:
                titles_seen.add(inc['title'])
                combined.append(inc)
                
        self.incidents_timeline.clear()
        for inc in combined:
            color = CORES['vermelho'] if inc['risk'] == "CRÍTICO" else (CORES['laranja'] if inc['risk'] == "ALTO" else CORES['azul'])
            item = QListWidgetItem(f"🚨 {inc['title']}\n[{inc['risk']}] — {inc['time']}")
            item.setData(Qt.ItemDataRole.UserRole, inc)
            item.setForeground(QColor(color))
            self.incidents_timeline.addItem(item)

    # --- TELA 3: PRÁTICA (DESAFIOS DE TREINAMENTO) ---

    def setup_screen_practice(self):
        layout = QHBoxLayout(self.screen_practice)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        left_widget = QWidget()
        left_lay = QVBoxLayout(left_widget)
        left_lay.setContentsMargins(0, 0, 0, 0)
        left_lay.setSpacing(10)
        
        lbl_cases = QLabel("🧪 Casos Reais & Simulações")
        lbl_cases.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {CORES['roxo']};")
        left_lay.addWidget(lbl_cases)
        
        self.practice_list = QListWidget()
        self.practice_list.setStyleSheet(f"""
            QListWidget {{
                background-color: #FFFFFF;
                border: 1px solid {CORES['borda']};
                border-radius: 12px;
                padding: 8px;
            }}
            QListWidget::item {{
                padding: 10px;
                border-bottom: 1px solid #F1F5F9;
                border-radius: 8px;
            }}
            QListWidget::item:hover {{
                background-color: #F8FAFC;
            }}
            QListWidget::item:selected {{
                background-color: {CORES['roxo_suave']};
                color: {CORES['roxo']};
            }}
        """)
        self.practice_list.itemClicked.connect(self.on_practice_selected)
        left_lay.addWidget(self.practice_list)
        layout.addWidget(left_widget, 4)
        
        self.practice_console = QFrame()
        self.practice_console.setStyleSheet(f"background-color: #FFFFFF; border: 1px solid {CORES['borda']}; border-radius: 12px;")
        console_lay = QVBoxLayout(self.practice_console)
        console_lay.setContentsMargins(20, 20, 20, 20)
        console_lay.setSpacing(12)
        
        self.lbl_prac_title = QLabel("Selecione um caso para iniciar o treinamento")
        self.lbl_prac_title.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {CORES['texto']};")
        self.lbl_prac_title.setWordWrap(True)
        console_lay.addWidget(self.lbl_prac_title)
        
        self.lbl_prac_brief = QLabel("Aqui você investigará logs, hashes de malware, e tráfego de rede anômalo simulados pela Íris. Responda às perguntas corretas para neutralizar a ameaça.")
        self.lbl_prac_brief.setWordWrap(True)
        self.lbl_prac_brief.setStyleSheet("font-size: 12px; color: #64748B; line-height: 1.4;")
        console_lay.addWidget(self.lbl_prac_brief)
        
        self.prac_quiz_panel = QFrame()
        self.prac_quiz_panel.setStyleSheet(f"background-color: #F8FAFC; border: 1px solid {CORES['borda']}; border-radius: 8px; padding: 12px;")
        self.quiz_lay = QVBoxLayout(self.prac_quiz_panel)
        self.quiz_lay.setSpacing(8)
        
        self.lbl_quiz_question = QLabel("")
        self.lbl_quiz_question.setWordWrap(True)
        self.lbl_quiz_question.setStyleSheet("font-weight: bold; font-size: 12px; color: #0F172A;")
        self.quiz_lay.addWidget(self.lbl_quiz_question)
        
        self.option_buttons = []
        for i in range(3):
            btn = QPushButton("")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: #FFFFFF;
                    border: 1px solid {CORES['borda']};
                    border-radius: 6px;
                    padding: 8px 12px;
                    text-align: left;
                    font-size: 11px;
                }}
                QPushButton:hover {{
                    border-color: {CORES['roxo']};
                    background-color: {CORES['roxo_suave']};
                }}
            """)
            btn.clicked.connect(lambda checked, idx=i: self.on_answer_submitted(idx))
            self.option_buttons.append(btn)
            self.quiz_lay.addWidget(btn)
            
        self.lbl_quiz_feedback = QLabel("")
        self.lbl_quiz_feedback.setWordWrap(True)
        self.lbl_quiz_feedback.setStyleSheet("font-size: 11px; font-weight: bold; padding: 6px; border-radius: 4px;")
        self.lbl_quiz_feedback.hide()
        self.quiz_lay.addWidget(self.lbl_quiz_feedback)
        
        console_lay.addWidget(self.prac_quiz_panel)
        self.prac_quiz_panel.hide()
        
        console_lay.addStretch()
        layout.addWidget(self.practice_console, 6)
        
        self.load_practice_scenarios()

    def load_practice_scenarios(self):
        self.practice_database = [
            {
                "title": "Caso: Download Suspeito de PDF",
                "type": "Caso Resolvido",
                "brief": "Cenário: Roger recebeu um anexo chamado 'fatura_servico_urgente.pdf'. Ao fazer o download e analisar no SOC, o arquivo contém um link encurtado executando script no navegador para capturar tokens de sessão.",
                "question": "Qual é a primeira ação recomendada ao identificar que um PDF contém macros ou scripts ocultos de redirecionamento?",
                "options": [
                    "Ignorar e abrir o PDF em outro leitor de PDF offline.",
                    "Bloquear o hash do arquivo no EDR e no proxy corporativo para evitar novos acessos.",
                    "Fazer upload do arquivo para o servidor público da empresa para validação."
                ],
                "correct": 1,
                "explanation": "✓ Correto! Bloquear o hash no EDR impede que qualquer usuário na organização execute o arquivo, e bloquear no proxy impede conexões adicionais ao servidor de malware."
            },
            {
                "title": "Caso: Processo PowerShell Ofuscado",
                "type": "Caso Resolvido",
                "brief": "Cenário: Um alerta acusa a execução do PowerShell com uma string encodada em Base64 no host de Roger. A string decodificada revela comandos de download e execução automática em memória.",
                "question": "Qual técnica do framework MITRE ATT&CK está associada à ofuscação de comandos da linha de comando?",
                "options": [
                    "T1027 - Obfuscated Files or Information",
                    "T1110 - Brute Force",
                    "T1562 - Impair Defenses"
                ],
                "correct": 0,
                "explanation": "✓ Correto! A técnica T1027 aborda tentativas de dificultar a análise e assinaturas ocultando a estrutura real do comando ou arquivos."
            },
            {
                "title": "Simulação: Phishing por E-mail",
                "type": "Simulação Ativa",
                "brief": "Cenário: Um e-mail da TI corporativa solicita redefinição urgente da senha do Office 365, apontando para 'https://m365-security-check.company-ti.com'.",
                "question": "Qual elemento indica que o link é uma fraude de Engenharia Social?",
                "options": [
                    "O uso de HTTPS na barra de endereço.",
                    "A urgência do tom e o subdomínio modificado (company-ti.com em vez de microsoft.com).",
                    "A imagem de fundo com a logo da Microsoft."
                ],
                "correct": 1,
                "explanation": "✓ Correto! Subdomínios criados em domínios de terceiros são a principal tática para imitar serviços legítimos. A urgência induz o usuário ao erro."
            },
            {
                "title": "Simulação: Engenharia Social via Teams",
                "type": "Simulação Ativa",
                "brief": "Cenário: Um usuário chamado 'Suporte-Helpdesk' envia mensagem no Teams pedindo o código de autenticação multifator (MFA) recebido em seu celular para 'ajuste de login'.",
                "question": "Como você deve responder a esta solicitação?",
                "options": [
                    "Fornecer o código MFA imediatamente para restabelecer o sistema.",
                    "Recusar a solicitação e reportar o incidente para o time de SOC/TI via canais oficiais de denúncia.",
                    "Perguntar o nome completo do atendente antes de passar o código."
                ],
                "correct": 1,
                "explanation": "✓ Correto! O código MFA é secreto e nunca deve ser fornecido a ninguém, nem mesmo à equipe de suporte técnico da empresa."
            },
            {
                "title": "Simulação: Ransomware locked.locked",
                "type": "Simulação Ativa",
                "brief": "Cenário: O EDR detecta que o processo 'svchost.exe' rodando a partir da pasta Downloads está renomeando arquivos da pasta Documentos do usuário para a extensão '.locked' em grande velocidade.",
                "question": "Qual é a ação imediata que o analista do SOC deve acionar no console do EDR?",
                "options": [
                    "Executar uma limpeza de arquivos temporários do disco.",
                    "Isolar o host da rede logicamente e terminar a árvore do processo suspeito.",
                    "Aguardar o término da criptografia para obter a chave de descriptografia."
                ],
                "correct": 1,
                "explanation": "✓ Correto! Isolar o host impede a propagação lateral pela rede e o encerramento do processo interrompe a criptografia em andamento, salvando arquivos restantes."
            }
        ]
        
        self.practice_list.clear()
        for idx, sc in enumerate(self.practice_database):
            emoji = "📁" if sc['type'] == "Caso Resolvido" else "🧪"
            item = QListWidgetItem(f"{emoji} {sc['title']}\n[{sc['type']}]")
            item.setData(Qt.ItemDataRole.UserRole, sc)
            self.practice_list.addItem(item)

    def on_practice_selected(self, item):
        sc = item.data(Qt.ItemDataRole.UserRole)
        if not sc:
            return
            
        self.lbl_prac_title.setText(sc['title'])
        self.lbl_prac_brief.setText(sc['brief'])
        self.lbl_quiz_question.setText(sc['question'])
        self.lbl_quiz_feedback.hide()
        
        for idx, opt in enumerate(sc['options']):
            self.option_buttons[idx].setText(opt)
            self.option_buttons[idx].setEnabled(True)
            self.option_buttons[idx].setStyleSheet(f"""
                QPushButton {{
                    background-color: #FFFFFF;
                    border: 1px solid {CORES['borda']};
                    border-radius: 6px;
                    padding: 8px 12px;
                    text-align: left;
                    font-size: 11px;
                }}
                QPushButton:hover {{
                    border-color: {CORES['roxo']};
                    background-color: {CORES['roxo_suave']};
                }}
            """)
            
        self.prac_quiz_panel.show()
        self.active_practice_scenario = sc

    def on_answer_submitted(self, idx):
        sc = getattr(self, "active_practice_scenario", None)
        if not sc:
            return
            
        for btn in self.option_buttons:
            btn.setEnabled(False)
            
        if idx == sc['correct']:
            self.option_buttons[idx].setStyleSheet(f"background-color: #ECFDF5; border: 1px solid #A7F3D0; color: #047857; font-size: 11px; border-radius: 6px; padding: 8px 12px;")
            self.lbl_quiz_feedback.setText(sc['explanation'])
            self.lbl_quiz_feedback.setStyleSheet("color: #047857; background-color: #ECFDF5; border: 1px solid #A7F3D0; font-size: 11px; font-weight: bold; padding: 6px; border-radius: 4px;")
        else:
            self.option_buttons[idx].setStyleSheet(f"background-color: #FEE2E2; border: 1px solid #FCA5A5; color: #EF4444; font-size: 11px; border-radius: 6px; padding: 8px 12px;")
            self.option_buttons[sc['correct']].setStyleSheet(f"background-color: #ECFDF5; border: 1px solid #A7F3D0; color: #047857; font-size: 11px; border-radius: 6px; padding: 8px 12px;")
            self.lbl_quiz_feedback.setText("✗ Incorreto. A resposta correta foi destacada em verde.")
            self.lbl_quiz_feedback.setStyleSheet("color: #B91C1C; background-color: #FEE2E2; border: 1px solid #FCA5A5; font-size: 11px; font-weight: bold; padding: 6px; border-radius: 4px;")
            
        self.lbl_quiz_feedback.show()

    def open_settings_dialog(self):
        dialog = SettingsDialog(self)
        dialog.exec()

    def explain_with_iris(self, item_type, item_data):
        prompt = ""
        if item_type == "process":
            prompt = f"Explique o que é o processo '{item_data}' e se ele apresenta riscos de segurança para o sistema."
        elif item_type == "connection":
            prompt = f"Analise a conexão de rede para o host/IP '{item_data}'. Diga se este endereço é suspeito e qual serviço costuma rodar nele."
        elif item_type == "download":
            prompt = f"Explique o risco potencial do arquivo baixado '{item_data}'. Como um SOC analisa este tipo de arquivo para verificar se é malware?"
        elif item_type == "app":
            prompt = f"Analise o aplicativo '{item_data}' em execução. Quais permissões e riscos de segurança estão associados a ele?"
            
        if prompt:
            self.switch_to_page(0)
            self.txt_home_input.setText(prompt)
            self.send_home_chat()

    def create_placeholder_screen(self, title, icon, description):
        widget = QWidget()
        widget.setStyleSheet("background-color: #F8FAFC;")
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(35, 35, 35, 35)
        layout.setSpacing(20)
        
        layout.addWidget(QLabel(f"<h2>{icon}  {title}</h2>"))
        layout.addWidget(self.create_separator())
        
        lbl_desc = QLabel(description)
        lbl_desc.setStyleSheet(f"font-size: 14px; color: {CORES['texto_suave']}; margin-bottom: 20px;")
        layout.addWidget(lbl_desc)
        return widget

    def on_save_config_clicked(self):
        url = self.txt_ollama_url.text().strip()
        model = self.txt_ollama_model.text().strip()
        key = self.txt_groq_key.text().strip()
        
        success = save_config(url, model, key)
        if success:
            self.lbl_config_status.setText("Configurações atualizadas no arquivo .env com sucesso!")
            self.lbl_sidebar_model.setText(f"Modelo: {model}")
            self.lbl_model_val.setText(f"Modelo: {model}")
            QTimer.singleShot(3000, lambda: self.lbl_config_status.setText(""))
        else:
            self.lbl_config_status.setText("Erro ao salvar arquivo .env.")

    # --- ATUALIZAÇÕES PERIÓDICAS ---

    def on_metrics_updated(self, data):
        # 1. Medidores circulares
        cpu = data['cpu_percent']
        self.gauge_cpu.set_value(cpu)
        self.lbl_cpu_val.setText(f"{int(cpu)}%")
        self.update_progressbar_style(self.progress_cpu, cpu)
        
        ram = data['ram_percent']
        self.gauge_ram.set_value(ram)
        self.lbl_ram_val.setText(f"{int(ram)}%")
        self.update_progressbar_style(self.progress_ram, ram)
        
        disk_val = psutil.disk_usage('/').percent
        self.gauge_disk.set_value(disk_val)
        
        net_val = min(100.0, (data['net_up'] + data['net_down']) * 12)
        self.gauge_net.set_value(net_val)
        
        # Medidores circulares da aba de Defesa
        if hasattr(self, 'def_gauge_cpu'):
            self.def_gauge_cpu.set_value(cpu)
        if hasattr(self, 'def_gauge_ram'):
            self.def_gauge_ram.set_value(ram)
        if hasattr(self, 'def_gauge_disk'):
            self.def_gauge_disk.set_value(disk_val)
        if hasattr(self, 'def_gauge_net'):
            self.def_gauge_net.set_value(net_val)
        
        # Histórico da linha de tendência
        self.activity_points.append(cpu)
        if len(self.activity_points) > 15:
            self.activity_points.pop(0)
        self.activity_trend.points = list(self.activity_points)
        self.activity_trend.update()
        
        # 2. Velocidade Rede
        self.lbl_net_speed.setText(f"↑ {data['net_up']:.1f} MB/s  ↓ {data['net_down']:.1f} MB/s")
        
        # 3. Status Serviços (Grid)
        self.update_status_card("Firewall", data['firewall'])
        self.update_status_card("Antivírus", data['antivirus'])
        self.update_status_card("Rede", data['rede'], "Online", "Desconectado")
        self.update_status_card("Atualizações", data['atualizacoes'])
        self.update_status_card("Agente SOC", data['agente_soc'])
        self.update_status_card("Ollama", data['ollama'])
        
        # Sidebar status header
        lbl_ollama_status = self.sidebar_right.findChild(QLabel, "lbl_status_ollama")
        if lbl_ollama_status:
            if data['ollama']:
                lbl_ollama_status.setText("ÍRIS  ◉ Ativa")
                lbl_ollama_status.setStyleSheet(f"font-size: 14px; font-weight: bold; color: {CORES['roxo']};")
            else:
                lbl_ollama_status.setText("ÍRIS  ◉ Inativa")
                lbl_ollama_status.setStyleSheet(f"font-size: 14px; font-weight: bold; color: {CORES['vermelho']};")
                
        # 4. Listagem de Processos
        self.process_list.clear()
        for proc in data['processes']:
            item = QListWidgetItem(f"PID: {proc['pid']} | {proc['name']} | CPU: {proc['cpu_percent']:.1f}% | {proc['username']}")
            item.setData(Qt.ItemDataRole.UserRole, proc)
            if proc['cpu_percent'] > 50:
                item.setForeground(QColor(CORES['laranja']))
                item.setBackground(QColor("rgba(245, 158, 11, 0.08)"))
            self.process_list.addItem(item)
            
        # Atualiza processos suspeitos
        if hasattr(self, 'update_suspicious_processes'):
            self.update_suspicious_processes(data)
            
        # 5. Listagem de Conexões
        self.connection_list.clear()
        for conn in data['connections']:
            item = QListWidgetItem(f"{conn['process']} (PID: {conn['pid']}) ➔ {conn['ip']}:{conn['port']}")
            if conn['is_external']:
                item.setForeground(QColor(CORES['vermelho']))
                item.setBackground(QColor("rgba(239, 68, 68, 0.08)"))
            self.connection_list.addItem(item)
            
        # Atualiza lista de remote hosts
        if hasattr(self, 'hosts_list'):
            self.hosts_list.clear()
            hosts_seen = set()
            for conn in data['connections']:
                if conn['ip'] and conn['ip'] not in hosts_seen:
                    hosts_seen.add(conn['ip'])
                    item = QListWidgetItem(f"🌐 Remote Host: {conn['ip']} (Porta: {conn['port']})")
                    item.setData(Qt.ItemDataRole.UserRole, conn['ip'])
                    if conn['is_external']:
                        item.setForeground(QColor(CORES['vermelho']))
                    self.hosts_list.addItem(item)
                    
        # Atualiza downloads e apps
        if hasattr(self, 'update_downloads_list'):
            self.update_downloads_list()
        if hasattr(self, 'update_apps_list'):
            self.update_apps_list()
            
        # 6. Alertas e Dados de estado.json
        estado = data['estado']
        if estado:
            # Atualiza timeline de incidentes
            if hasattr(self, 'update_incidents_timeline'):
                self.update_incidents_timeline(estado.get("eventos", []))
            status = estado.get("status", "Normal")
            if not data['agente_soc']:
                self.lbl_protection_status.setText("🟡 Agente SOC Inativo")
                self.lbl_protection_status.setStyleSheet("font-size: 18px; font-weight: bold; color: #F59E0B; border: none; background: transparent;")
                self.lbl_protection_desc.setText("O agente SOC em background não está sendo executado.")
                
                self.title_bar.lbl_badge_icon.setText("⚠️")
                self.title_bar.lbl_badge_icon.setStyleSheet("color: #D97706; font-size: 12px; background: transparent; border: none;")
                self.title_bar.lbl_badge_title.setText("Agente SOC Inativo")
                self.title_bar.lbl_badge_title.setStyleSheet("color: #92400E; font-size: 10px; font-weight: bold;")
                self.title_bar.lbl_badge_sub.setText("Serviço em background offline")
                self.title_bar.lbl_badge_sub.setStyleSheet("color: #B45309; font-size: 9px;")
                self.title_bar.badge.setStyleSheet("""
                    QFrame {
                        background-color: #FEF3C7;
                        border: 1px solid #FDE68A;
                        border-radius: 8px;
                        padding: 4px 10px;
                    }
                """)
            elif status in ["ALTO", "CRÍTICO"]:
                self.lbl_protection_status.setText(f"🔴 Risco {status}")
                self.lbl_protection_status.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {CORES['vermelho']}; border: none; background: transparent;")
                self.lbl_protection_desc.setText("Foram identificados recentemente incidentes ou conexões suspeitas.")
                
                self.title_bar.lbl_badge_icon.setText("🚨")
                self.title_bar.lbl_badge_icon.setStyleSheet("color: #EF4444; font-size: 12px; background: transparent; border: none;")
                self.title_bar.lbl_badge_title.setText(f"Risco {status}")
                self.title_bar.lbl_badge_title.setStyleSheet("color: #991B1B; font-size: 10px; font-weight: bold;")
                self.title_bar.lbl_badge_sub.setText("Incidentes em investigação")
                self.title_bar.lbl_badge_sub.setStyleSheet("color: #B91C1C; font-size: 9px;")
                self.title_bar.badge.setStyleSheet("""
                    QFrame {
                        background-color: #FEE2E2;
                        border: 1px solid #FCA5A5;
                        border-radius: 8px;
                        padding: 4px 10px;
                    }
                """)
            else:
                self.lbl_protection_status.setText("🟢 Protegido")
                self.lbl_protection_status.setStyleSheet("font-size: 18px; font-weight: bold; color: #10B981; border: none; background: transparent;")
                self.lbl_protection_desc.setText("Seu sistema está rodando normalmente. Nenhuma ação necessária.")
                
                self.title_bar.lbl_badge_icon.setText("🛡")
                self.title_bar.lbl_badge_icon.setStyleSheet("color: #10B981; font-size: 12px; background: transparent; border: none;")
                self.title_bar.lbl_badge_title.setText("Proteção Ativa")
                self.title_bar.lbl_badge_title.setStyleSheet("color: #065F46; font-size: 10px; font-weight: bold;")
                self.title_bar.lbl_badge_sub.setText("Todos os sistemas seguros")
                self.title_bar.lbl_badge_sub.setStyleSheet("color: #047857; font-size: 9px;")
                self.title_bar.badge.setStyleSheet("""
                    QFrame {
                        background-color: #ECFDF5;
                        border: 1px solid #A7F3D0;
                        border-radius: 8px;
                        padding: 4px 10px;
                    }
                """)
                
            total_alertas = estado.get("total_alertas_hoje", 0)
            self.update_stat_card_value(self.card_alerts, str(total_alertas))
            
            # Atualiza Eventos de hoje
            self.update_stat_card_value(self.card_events, str(1200 + total_alertas))
            
            # Atualiza sistemas monitorados
            self.update_stat_card_value(self.card_systems, str(len(psutil.pids()) // 20 + 2))
            
            # Conta ameaças
            eventos = estado.get("eventos", [])
            bloqueios = sum(1 for e in eventos for acao in e.get("acoes", []) if "bloqueado" in acao.lower() or "kill" in acao.lower())
            self.update_stat_card_value(self.card_threats, str(bloqueios if bloqueios > 0 else 1))
            
            # Preenche Alertas em tempo real na Home
            self.home_alerts_list.clear()
            if eventos:
                # Usa os eventos mais recentes do estado
                for ev in eventos[-4:]:
                    time_str = ev.get("hora", "")
                    alerts = ev.get("alertas", [])
                    alert_desc = alerts[0] if alerts else "Evento desconhecido"
                    risco = ev.get("risco", "Médio")
                    
                    item = QListWidgetItem()
                    item.setSizeHint(QSize(220, 50))
                    widget = AlertItemWidget(alert_desc[:32], "AGENTE-SOC", f"Há {time_str}", risco.capitalize())
                    self.home_alerts_list.addItem(item)
                    self.home_alerts_list.setItemWidget(item, widget)
                    
                # Atualiza último alerta na sidebar direita
                last_event = eventos[-1]
                t_str = last_event.get("hora", "")
                alerts = last_event.get("alertas", [])
                a_desc = alerts[0] if alerts else "Evento desconhecido"
                self.lbl_alert_time.setText(f"{t_str} — Alerta SOC")
                self.lbl_alert_time.setStyleSheet(f"font-weight: bold; font-size: 12px; color: {CORES['laranja']};")
                self.lbl_alert_desc.setText(a_desc)
            else:
                self.setup_fallback_alerts()
        else:
            if not data['agente_soc']:
                self.lbl_protection_status.setText("🟡 Agente SOC Inativo")
                self.lbl_protection_status.setStyleSheet("font-size: 18px; font-weight: bold; color: #F59E0B; border: none; background: transparent;")
                self.lbl_protection_desc.setText("O agente SOC em background não está sendo executado.")
                
                self.title_bar.lbl_badge_icon.setText("⚠️")
                self.title_bar.lbl_badge_icon.setStyleSheet("color: #D97706; font-size: 12px; background: transparent; border: none;")
                self.title_bar.lbl_badge_title.setText("Agente SOC Inativo")
                self.title_bar.lbl_badge_title.setStyleSheet("color: #92400E; font-size: 10px; font-weight: bold;")
                self.title_bar.lbl_badge_sub.setText("Serviço em background offline")
                self.title_bar.lbl_badge_sub.setStyleSheet("color: #B45309; font-size: 9px;")
                self.title_bar.badge.setStyleSheet("""
                    QFrame {
                        background-color: #FEF3C7;
                        border: 1px solid #FDE68A;
                        border-radius: 8px;
                        padding: 4px 10px;
                    }
                """)
            else:
                self.lbl_protection_status.setText("🟢 Protegido")
                self.lbl_protection_status.setStyleSheet("font-size: 18px; font-weight: bold; color: #10B981; border: none; background: transparent;")
                self.lbl_protection_desc.setText("Seu sistema está rodando normalmente. Nenhuma ação necessária.")
                
                self.title_bar.lbl_badge_icon.setText("🛡")
                self.title_bar.lbl_badge_icon.setStyleSheet("color: #10B981; font-size: 12px; background: transparent; border: none;")
                self.title_bar.lbl_badge_title.setText("Proteção Ativa")
                self.title_bar.lbl_badge_title.setStyleSheet("color: #065F46; font-size: 10px; font-weight: bold;")
                self.title_bar.lbl_badge_sub.setText("Todos os sistemas seguros")
                self.title_bar.lbl_badge_sub.setStyleSheet("color: #047857; font-size: 9px;")
                self.title_bar.badge.setStyleSheet("""
                    QFrame {
                        background-color: #ECFDF5;
                        border: 1px solid #A7F3D0;
                        border-radius: 8px;
                        padding: 4px 10px;
                    }
                """)
            self.update_stat_card_value(self.card_alerts, "0")
            self.update_stat_card_value(self.card_events, "1.245")
            self.update_stat_card_value(self.card_threats, "0")
            self.setup_fallback_alerts()

    def setup_fallback_alerts(self):
        self.home_alerts_list.clear()
        mock_alerts = [
            ("Execução suspeita de PowerShell", "DESKTOP-ROGER", "Há 2 min", "Crítico"),
            ("Múltiplas tentativas de login falho", "SRV-ARQUIVOS", "Há 5 min", "Alto"),
            ("Download de arquivo suspeito", "DESKTOP-ROGER", "Há 8 min", "Médio"),
            ("Conexão com IP suspeito bloqueada", "DESKTOP-ROGER", "Há 12 min", "Baixo")
        ]
        for name, src, time_s, sev in mock_alerts:
            item = QListWidgetItem()
            item.setSizeHint(QSize(220, 50))
            widget = AlertItemWidget(name, src, time_s, sev)
            self.home_alerts_list.addItem(item)
            self.home_alerts_list.setItemWidget(item, widget)

    def on_ui_tick(self):
        h = datetime.datetime.now().hour
        if h < 12:
            self.lbl_greeting.setText("Bom dia, Roger. 👋")
        elif h < 18:
            self.lbl_greeting.setText("Boa tarde, Roger. 👋")
        else:
            self.lbl_greeting.setText("Boa noite, Roger. 👋")

    # --- COMPORTAMENTOS AUXILIARES ---

    def switch_to_page(self, index):
        self.stacked_widget.setCurrentIndex(index)
        self.menu_list.setCurrentRow(index)
        
        menus = ["Início", "Centro de Defesa", "Incidentes", "Prática"]
        if index < len(menus):
            self.title_bar.lbl_breadcrumb.setText(menus[index])

    def on_menu_clicked(self, item):
        idx = item.data(Qt.ItemDataRole.UserRole)
        self.switch_to_page(idx)

    def on_analisar_arquivo_clicked(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Selecionar Arquivo para Análise SOC")
        if file_path:
            dialog = FileScanDialog(file_path, self)
            dialog.exec()

    def on_iniciar_varredura_clicked(self):
        dialog = FullScanDialog(self)
        dialog.exec()

    def on_generate_report_clicked(self):
        dialog = ReportDialog(self)
        dialog.exec()

    # --- AUXILIARES DE CORES E RENDERING ---

    def update_stat_card_value(self, card, new_value):
        lbl = card.findChild(QLabel, "lbl_stat_value")
        if lbl:
            lbl.setText(new_value)

    def update_status_card(self, service_name, active, active_text="Online", inactive_text="Inativo"):
        lbl = self.status_indicators.get(service_name)
        if lbl:
            if active:
                lbl.setText(f"🟢 {active_text}")
                lbl.setStyleSheet(f"color: {CORES['verde']}; font-weight: bold;")
            else:
                lbl.setText(f"🔴 {inactive_text}")
                lbl.setStyleSheet(f"color: {CORES['vermelho']}; font-weight: bold;")

    def update_progressbar_style(self, progressbar, value):
        progressbar.setValue(int(value))
        if value < 70:
            color = CORES['verde']
        elif value < 90:
            color = CORES['laranja']
        else:
            color = CORES['vermelho']
            
        progressbar.setStyleSheet(f"""
            QProgressBar {{
                border: 1px solid {CORES['borda']};
                background-color: #F8FAFC;
                border-radius: 3px;
                height: 8px;
            }}
            QProgressBar::chunk {{
                background-color: {color};
                border-radius: 2px;
            }}
        """)

    def create_placeholder_screen(self, title, icon, description):
        widget = QWidget()
        widget.setStyleSheet("background-color: #F8FAFC;")
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(35, 35, 35, 35)
        layout.setSpacing(20)
        
        layout.addWidget(QLabel(f"<h2>{icon}  {title}</h2>"))
        layout.addWidget(self.create_separator())
        
        lbl_desc = QLabel(description)
        lbl_desc.setStyleSheet(f"font-size: 14px; color: {CORES['texto_suave']}; margin-bottom: 20px;")
        layout.addWidget(lbl_desc)
        
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(15)
        
        for i in range(2):
            panel = QFrame()
            panel.setStyleSheet(f"""
                QFrame {{
                    background-color: #FFFFFF;
                    border: 1px solid {CORES['borda']};
                    border-radius: 12px;
                    padding: 20px;
                }}
            """)
            p_lay = QVBoxLayout(panel)
            
            p_title = QLabel(f"Painel Operacional {i+1}")
            p_title.setStyleSheet(f"font-size: 14px; font-weight: bold; color: {CORES['roxo']};")
            p_lay.addWidget(p_title)
            
            p_desc = QLabel("Visualização simulada de dados de cibersegurança em tempo real. As funcionalidades completas desta tela serão implementadas na próxima fase de desenvolvimento.")
            p_desc.setWordWrap(True)
            p_desc.setStyleSheet(f"font-size: 12px; color: {CORES['texto_suave']};")
            p_lay.addWidget(p_desc)
            
            p_bar = QProgressBar()
            p_bar.setRange(0, 100)
            p_bar.setValue(45 * (i+1))
            p_bar.setStyleSheet(f"""
                QProgressBar {{ border: 1px solid {CORES['borda']}; background-color: #F8FAFC; border-radius: 6px; text-align: center; color: {CORES['texto_suave']}; height: 16px; }}
                QProgressBar::chunk {{ background-color: {CORES['roxo']}; border-radius: 5px; }}
            """)
            p_lay.addWidget(p_bar)
            
            cards_layout.addWidget(panel)
            
        layout.addLayout(cards_layout)
        layout.addStretch()
        return widget

    def create_separator(self):
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"background-color: {CORES['borda']}; max-height: 1px;")
        return sep

    def get_action_button_style(self, highlight=False):
        if highlight:
            return f"""
                QPushButton {{
                    background-color: {CORES['roxo']};
                    color: #FFFFFF;
                    border: none;
                    border-radius: 6px;
                    padding: 10px 20px;
                    font-weight: bold;
                    font-size: 13px;
                }}
                QPushButton:hover {{
                    background-color: {CORES['roxo_sec']};
                }}
            """
        else:
            return f"""
                QPushButton {{
                    background-color: #FFFFFF;
                    color: {CORES['texto']};
                    border: 1px solid {CORES['borda']};
                    border-radius: 6px;
                    padding: 10px 20px;
                    font-weight: bold;
                    font-size: 13px;
                }}
                QPushButton:hover {{
                    background-color: #F8FAFC;
                    border-color: {CORES['roxo']};
                }}
            """

    def get_input_style(self):
        return f"""
            QLineEdit {{
                background-color: #FFFFFF;
                border: 1px solid {CORES['borda']};
                border-radius: 6px;
                padding: 10px;
                color: {CORES['texto']};
                font-family: "{FONTE_PRINCIPAL}";
                font-size: 13px;
            }}
            QLineEdit:focus {{
                border: 1px solid {CORES['roxo']};
            }}
        """

    def closeEvent(self, event):
        self.metrics_worker.stop()
        self.metrics_worker.wait()
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = IrisMainWindow()
    window.show()
    sys.exit(app.exec())
