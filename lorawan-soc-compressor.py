import re
import unicodedata


#Prueba 2 Omniasec
#Realizado por: Luis Vega Silva

def comprimir_mensaje(texto):
    if not texto:
        return ""

    # --- PASO 1: Normalización (mayúsculas + eliminar diacríticos) ---
    t = texto.upper()
    t = ''.join(c for c in unicodedata.normalize('NFD', t) if unicodedata.category(c) != 'Mn')

    # --- PASO 2: Extracción de IOCs ---
    iocs = []
    # IPs (tipado implícito, una IP se reconoce sola)
    for m in re.finditer(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', t):
        ip = m.group(1)
        if ip not in iocs:
            iocs.append(ip)
    # Puertos (compacto: P53 en lugar de PUERTO 53)
    for m in re.finditer(r'\bPUERTO\s+(\d+)\b', t):
        iocs.append(f"P{m.group(1)}")
    # Usuarios (negative lookahead para evitar falsos positivos)
    for m in re.finditer(r'\bUSUARIO\s+(?!NO\b|UN\b|EL\b|LA\b|QUE\b|DE\b)([\'"]?[\w_-]+[\'"]?)\b', t):
        usr = m.group(1).strip("'").strip('"')
        iocs.append(f"U:{usr}")

    # --- PASO 3: Severidad (símbolo mínimo) ---
    urgente = bool(re.search(r'\b(URGENTE|INMEDIAT[OA])\b', t))
    critico = bool(re.search(r'\b(CRITIC[OA])\b', t))
    if critico:
        sev = "!!"
    elif urgente:
        sev = "!"
    else:
        sev = "?"

    # --- PASO 4: Extracción de Acción Requerida (específica primero, genérica después) ---
    acciones_especificas = [
        (r'\b(BLOQUEO|BLOQUEAR).{0,30}\b(IP|DIRECCION IP)\b', "BLK-IP"),
        (r'\b(BLOQUEO|DESACTIVACION|SUSPENSION).{0,30}\b(CUENTA|USUARIO)\b', "BLK-USR"),
        (r'\b(BLOQUEO|BLOQUEAR).{0,30}\bCORTAFUEGOS\b', "BLK-FW"),
        (r'\b(BLOQUEO|CIERRE).{0,30}\bPUERTO\b', "BLK-PORT"),
    ]
    acciones_genericas = [
        (r'\b(BLOQUEO|BLOQUEAR)\b', "BLK"),
        (r'\b(AISLAMIENTO|AISLAR)\b', "ISO"),
        (r'\b(CAMBIO DE CONTRASENA)\b', "RST-PWD"),
        (r'\b(REVOCACION|REVOCAR)\b', "RVK"),
        (r'\b(AUDITORIA|AUDITAR)\b', "AUDIT"),
        (r'\b(TERMINAR|FINALIZAR|MATAR)\b', "TERM"),
        (r'\b(SUSPENSION|SUSPENDER)\b', "SUSP"),
        (r'\b(DESACTIVACION|DESACTIVAR)\b', "DEACT"),
        (r'\b(INTERVENCION|INTERVENIR)\b', "INTRV"),
    ]
    acciones = []
    # Primero las específicas (BLK-IP, BLK-USR, etc.)
    for patron, abrev in acciones_especificas:
        if re.search(patron, t):
            if abrev not in acciones:
                acciones.append(abrev)
    # Luego las genéricas, pero BLK genérico solo si no hay BLK específico
    for patron, abrev in acciones_genericas:
        if re.search(patron, t):
            if abrev == "BLK" and any(a.startswith("BLK-") for a in acciones):
                continue  # ya hay un BLK específico, no duplicar
            if abrev not in acciones:
                acciones.append(abrev)
    accion_str = "+".join(acciones)

    # --- PASO 5: Eliminar del texto lo que ya fue extraído ---
    # Quitar IPs (ya están en iocs)
    t = re.sub(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', '', t)
    # Quitar puertos explícitos (ya están en iocs como P53)
    t = re.sub(r'\bPUERTO\s+\d+\b', '', t)
    # Quitar usuarios explícitos (ya están en iocs)
    # Evitar eliminar frases como 'USUARIO NO AUTORIZADO' usando lookahead
    t = re.sub(r'\bUSUARIO\s+(?!NO\b|UN\b|EL\b|LA\b|QUE\b|DE\b)[\'\"]?[\w_-]+[\'\"]?\b', '', t)
    # Quitar triggers de acción (ya están en accion_str)
    for patron, _ in acciones_especificas + acciones_genericas:
        t = re.sub(patron, '', t)
    # Quitar triggers de severidad (ya están en sev)
    t = re.sub(r'\b(CRITIC[OA]|URGENTE|INMEDIAT[OA])\b', '', t)

    # --- PASO 6: Poda de Relleno Operativo (frases sin valor) ---
    FILLER = [
        r'\bSE HA(N)?\s+(DETECTADO|REGISTRADO|REPORTADO|OBSERVADO)\b',
        r'\bHEMOS DETECTADO\b',
        r'\bSOLICITAMOS\b',
        r'\bES NECESARIO\b',
        r'\bES URGENTE\b',
        r'\bPOR FAVOR\b',
        r'\bDE FORMA\b',
        r'\bDE MANERA\b',
        r'\bPROVIENEN DE\b',
        r'\bALERTA DE\b',
        r'\bALERTA POR\b',
        r'\bIP DE ORIGEN\b',
        r'\bDIRECCION IP\b',
        r'\bLA IP\b',
    ]
    for f in FILLER:
        t = re.sub(f, '', t)

    # --- PASO 7: Eliminar stopwords (artículos, preposiciones, etc.) ---
    STOPWORDS = {
        'UN', 'UNA', 'UNOS', 'UNAS', 'EL', 'LA', 'LOS', 'LAS',
        'DE', 'DEL', 'AL', 'A', 'EN', 'POR', 'CON', 'PARA', 'SIN',
        'QUE', 'Y', 'E', 'O', 'U', 'SU', 'SUS', 'ES', 'SON',
        'HA', 'HAN', 'SE', 'LO', 'LE', 'MAS', 'MUY',
        'DESDE', 'HACIA', 'CONTRA', 'ENTRE', 'SOBRE',
        'ESTA', 'ESTAN', 'HAY', 'HEMOS',
        'REALIZAR', 'FORMA',
    }
    tokens = t.split()
    tokens = [tok for tok in tokens if tok.strip('.,;:()') not in STOPWORDS]

    # --- PASO 8: Limpiar puntuación residual y tokens vacíos ---
    tokens = [re.sub(r'[.,;:\'"()\[\]{}]', '', tok) for tok in tokens]
    tokens = [tok for tok in tokens if len(tok) > 1]  # eliminar tokens de 1 char

    # --- PASO 9: Abreviaciones estándar SOC (antes de disemvowel) ---
    # Primero frases multi-palabra (se aplican sobre el texto unido)
    ABREV_FRASES = [
        (r'\bDENEGACION SERVICIO\b', 'DDOS'),
        (r'\bFUERZA BRUTA\b', 'BF'),
        (r'\bBASE DATOS\b', 'BD'),
        (r'\bDARK WEB\b', 'DARKWEB'),
        (r'\bRED LOCAL\b', 'LAN'),
        (r'\bINICIO SESION\b', 'LOGIN'),
        (r'\bESCALADA PRVLGS\b', 'PRIVESC'),
        (r'\bESCALADA PRIVILEGIOS\b', 'PRIVESC'),
        (r'\bNO AUTORIZAD[OA]S?\b', 'UNAUTH'),
        (r'\bNO ATRZD[OA]S?\b', 'UNAUTH'),
    ]
    texto_unido = ' '.join(tokens)
    for patron, abrev in ABREV_FRASES:
        texto_unido = re.sub(patron, abrev, texto_unido)
    # Map negated authorization phrases to UNAUTH before individual-word abbreviations
    texto_unido = re.sub(r'\bNO\s+AUTORIZAD[OA]S?\b', 'UNAUTH', texto_unido)
    texto_unido = re.sub(r'\bNO\s+ATRZD[OA]S?\b', 'UNAUTH', texto_unido)
    tokens = texto_unido.split()

    # Luego palabras individuales
    ABREV_PALABRAS = {
        'SERVIDOR': 'SRV', 'SERVIDORES': 'SRV',
        'CORTAFUEGOS': 'FW',
        'VULNERABILIDAD': 'VULN', 'VULNERABILIDADES': 'VULN',
        'EXFILTRACION': 'EXFIL',
        'CREDENCIALES': 'CREDS',
        'CONEXIONES': 'CONN', 'CONEXION': 'CONN',
        'COMUNICACION': 'COMM',
        'SEGURIDAD': 'SEC',
        'PERIMETRAL': 'PMTR',
        'APLICACIONES': 'APP',
        'PRODUCCION': 'PROD',
        'ORIGEN': 'SRC',
        'DESTINO': 'DST',
        'TRAFICO': 'TRFC',
        'PETICIONES': 'REQ',
        'INTENTOS': 'INTNT',
        'PROCESOS': 'PROCS',
        'ARCHIVOS': 'FILES',
        'SESION': 'SESS', 'SESIONES': 'SESS',
        'CONTRASENA': 'PWD',
        'CUENTA': 'ACCT',
        'SISTEMA': 'SYS',
        'ACCESO': 'ACCESS',
        'DATOS': 'DATA',
        'PERSISTENTE': 'PRSTNT',
        'AUTORIZADAS': 'AUTH', 'AUTORIZADO': 'AUTH',
        'ATAQUE': 'ATK',
        'MULTIPLES': 'MULT',
        'FALLIDOS': 'FAIL', 'FALLIDAS': 'FAIL', 'FALLIDO': 'FAIL',
        'PRINCIPAL': 'MAIN',
        'EXTERNO': 'EXT', 'EXTERNA': 'EXT',
        'DETECTADA': 'DTCTD', 'DETECTADO': 'DTCTD',
        'PERSONAL': 'STAFF',
        'APERTURA': 'OPEN',
        'DESCARGA': 'DWNLD',
        'MASIVA': 'MASS', 'MASIVO': 'MASS',
        'TRANSFERENCIA': 'XFER',
        'VOLUMEN': 'VOL',
        'ACTIVIDAD': 'ACTV',
        'COMANDO': 'CMD',
        'CONTROL': 'CTRL',
        'CENTRO': 'CTR',
        'EQUIPO': 'HOST',
        'MONITORIZACION': 'MON',
        'REPOSITORIO': 'REPO', 'REPOSITORIOS': 'REPO',
        'FISICO': 'PHYS', 'FISICA': 'PHYS',
        'PERMISOS': 'PERMS',
        'SUPERUSUARIO': 'ROOT',
        'VINCULADOS': 'LNKD',
        'COINCIDENCIA': 'MATCH',
        'AUMENTO': 'SPIKE',
        'SATURANDO': 'SAT',
        'INUSUAL': 'ANOML',
    }
    tokens = [ABREV_PALABRAS.get(tok, tok) for tok in tokens]

    # --- PASO 10: Disemvoweling de palabras largas (>5 chars) ---
    # Solo para palabras que NO fueron abreviadas en el paso anterior
    def disemvowel(word):
        # Proteger: números, IPs, nombres con guión bajo, ya acrónimos
        if re.match(r'^\d', word):    return word  # empieza con número
        if '_' in word:               return word  # nombre de usuario
        # Proteger acrónimos completos en mayúsculas (p.ej. DDOS, UNAUTH)
        if re.match(r'^[A-Z]{2,}$', word): return word
        if len(word) <= 5:            return word  # corta: no tocar
        # Conservar primera vocal para legibilidad, quitar el resto
        primera = word[0]
        resto = re.sub(r'[AEIOU]', '', word[1:])
        # Colapsar consonantes dobles
        resto = re.sub(r'(.)\1+', r'\1', resto)
        result = primera + resto
        # Si quedó demasiado corto (< 3), devolver original truncado
        if len(result) < 3:
            return word[:5]
        return result

    tokens = [disemvowel(tok) for tok in tokens]

    # --- PASO 10: Ensamblado ---
    # Orden implícito: SEVERIDAD  TEXTO_COMPRIMIDO  IOCs  ACCIÓN
    # Sin etiquetas, sin separadores estáticos
    partes = [sev]

    # El texto comprimido ES la descripción del evento (genérico)
    texto_comprimido = ' '.join(tokens)
    if texto_comprimido:
        partes.append(texto_comprimido)

    # IOCs sin prefijo (tipado implícito)
    if iocs:
        partes.extend(iocs)

    # Acción
    if accion_str:
        partes.append(accion_str)

    return ' '.join(partes)