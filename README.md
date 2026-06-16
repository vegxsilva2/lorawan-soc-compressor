# Tactical Incident Compressor for LoRaWAN (SOC) 📡💼

Este repositorio contiene una solución en Python diseñada para optimizar las comunicaciones de emergencia de un Centro de Operaciones de Seguridad (SOC) en escenarios de infraestructura crítica caídas.

## 📋 El Escenario del Desafío
Durante un ataque DDoS masivo, los enlaces de fibra habituales quedan saturados o completamente inoperativos. Para mantener la comunicación con el exterior, el SOC habilita una antena de emergencia con tecnología **LoRaWAN**.

* **El Problema:** El ancho de banda en LoRaWAN es extremadamente minúsculo.
* **La Restricción:** Al otro lado de la línea hay un analista humano, por lo que no se pueden emplear algoritmos de compresión estándar (como ZIP o GZIP). El mensaje resultante debe ser **interpretable directamente por una persona**.

## 🛠️ Mi Solución (`prueba-2-omniasec.py`)
Desarrollé una función llamada `comprimir_mensaje(texto)` basada en **estrategias de compresión lingüística y normalización semántica** aplicadas al contexto de la ciberseguridad.

La lógica del script procesa el lenguaje natural a través del siguiente pipeline:
1. **Normalización:** Conversión a mayúsculas y eliminación de diacríticos.
2. **Extracción Estructurada de IoCs:** Aislamiento automatizado de IPs, puertos (ej. `P53`) y usuarios (`U:usuario`).
3. **Mapeo de Severidad:** Reducción de calificativos de urgencia a símbolos tácticos (`!`, `!!`, `?`).
4. **Tipado de Acciones SOC:** Conversión de peticiones complejas en acrónimos operativos estándar (ej. `BLOQUEAR IP` -> `BLK-IP`, `AISLAR` -> `ISO`).
5. **Poda de Relleno Operativo:** Eliminación de *stopwords* y frases de cortesía o redundantes en un reporte de incidentes.
6. **Abreviación Semántica SOC:** Mapeo de vocabulario técnico a jerga compacta de seguridad (ej. `CORTAFUEGOS` -> `FW`, `TRAFICO` -> `TRFC`).
7. **Disemvoweling Controlado:** Reducción de longitud en palabras largas no abreviadas mediante la eliminación estratégica de vocales, conservando la primera letra para garantizar la legibilidad humana.

---

## 📊 Demostración de Rendimiento (~74% de Compresión)

### 📥 Mensaje de Entrada (Texto Original):
> *"Se ha detectado un aumento inusual de tráfico UDP en el puerto 53. La IP de origen es 192.168.1.45 y está saturando el cortafuegos perimetral. Solicitamos bloqueo inmediato de la IP."*
> *(178 caracteres)*

### 📤 Mensaje de Salida (Comprimido por el Script):
> `! SPIKE ANOML TRFC UDP 192.168.1.45 P53 BLK-IP`
> *(46 caracteres)*

* **Tasa de reducción de tamaño:** ~74.1%
* **Interpretabilidad:** Un analista de seguridad lee el output instantáneamente como: *"¡Urgente! Pico anómalo de tráfico UDP en la IP 192.168.1.45, puerto 53. Acción: Bloquear IP"*.

---

## 🚀 Cómo Ejecutarlo
El script utiliza únicamente la librería estándar de Python (`re` y `unicodedata`), por lo que no requiere dependencias externas.

```python
from prueba_2_omniasec import comprimir_mensaje

texto_incidente = "Se ha detectado un aumento inusual de tráfico UDP..."
print(comprimir_mensaje(texto_incidente))
