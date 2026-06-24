import sys
import os

# Baseline dict: key_path -> value_string
baseline_registro = {}

def obter_valores_registro():
    """
    Varre chaves críticas de persistência no registro do Windows (Run e Services).
    Retorna um dicionário mapeando o caminho completo da chave/valor ao seu conteúdo.
    Em plataformas não-Windows, retorna um dicionário vazio.
    """
    valores = {}
    if not sys.platform.startswith("win32"):
        return valores

    try:
        import winreg
    except ImportError:
        return valores

    # 1. HKLM Run
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_READ) as hkey:
            i = 0
            while True:
                try:
                    nome, valor, tipo = winreg.EnumValue(hkey, i)
                    valores[f"HKLM\\Run\\{nome}"] = str(valor)
                    i += 1
                except OSError:
                    break
    except Exception:
        pass

    # 2. HKCU Run
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_READ) as hkey:
            i = 0
            while True:
                try:
                    nome, valor, tipo = winreg.EnumValue(hkey, i)
                    valores[f"HKCU\\Run\\{nome}"] = str(valor)
                    i += 1
                except OSError:
                    break
    except Exception:
        pass

    # 3. HKLM Services
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"System\CurrentControlSet\Services", 0, winreg.KEY_READ) as hkey:
            i = 0
            while True:
                try:
                    nome_subkey = winreg.EnumKey(hkey, i)
                    i += 1
                    try:
                        with winreg.OpenKey(hkey, nome_subkey, 0, winreg.KEY_READ) as subkey:
                            try:
                                valor_img, tipo_img = winreg.QueryValueEx(subkey, "ImagePath")
                                valores[f"HKLM\\Services\\{nome_subkey}"] = str(valor_img)
                            except OSError:
                                # Se não tiver ImagePath, registra a existência da subchave
                                valores[f"HKLM\\Services\\{nome_subkey}"] = "Existe"
                    except Exception:
                        pass
                except OSError:
                    break
    except Exception:
        pass

    return valores

def construir_baseline_registro():
    """
    Popula o baseline inicial com o estado do registro na inicialização do agente.
    """
    global baseline_registro
    print("🔑 Construindo baseline do registro do Windows...")
    baseline_registro = obter_valores_registro()
    print(f"✅ Baseline do registro construído: {len(baseline_registro)} chaves monitoradas.")

def verificar_alteracoes_registro():
    """
    Verifica se novas chaves de persistência foram inseridas ou modificadas desde o último ciclo.
    """
    alertas = []
    global baseline_registro
    if not sys.platform.startswith("win32"):
        return alertas

    valores_atuais = obter_valores_registro()
    
    # Compara o estado atual com o baseline
    for chave, valor in valores_atuais.items():
        if chave not in baseline_registro:
            alertas.append({
                'tipo': 'registro_persistência_novo',
                'mensagem': f"🚨 PERSISTÊNCIA DETECTADA — Nova entrada no registro: {chave} -> {valor}",
                'detalhes': {'chave': chave, 'valor': valor}
            })
            baseline_registro[chave] = valor
        elif baseline_registro[chave] != valor:
            alertas.append({
                'tipo': 'registro_persistência_modificado',
                'mensagem': f"🚨 PERSISTÊNCIA DETECTADA — Entrada modificada no registro: {chave} -> de '{baseline_registro[chave]}' para '{valor}'",
                'detalhes': {'chave': chave, 'valor': valor}
            })
            baseline_registro[chave] = valor

    # Detecta chaves removidas
    chaves_removidas = [c for c in baseline_registro if c not in valores_atuais]
    for chave in chaves_removidas:
        alertas.append({
            'tipo': 'registro_persistência_removido',
            'mensagem': f"⚠️  Registro removido: {chave}",
            'detalhes': {'chave': chave}
        })
        del baseline_registro[chave]

    return alertas
