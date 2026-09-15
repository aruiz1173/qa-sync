# QA Sync · TestRail Vision

Aplicación web local para observar un recorrido real en Android o iOS y convertirlo en una propuesta de actualización para un caso de TestRail.

Es una aplicación standalone de código propio. La interfaz Squarish, el servidor, la captura, el análisis y la integración con TestRail viven en este mismo proyecto, sin runtimes internos, brokers externos ni componentes administrados.

```text
Navegador local ── HTTP loopback ── QA Sync Python
                                      ├─ TestRail
                                      ├─ Codex / Claude / OpenAI API
                                      ├─ Android: adb + scrcpy
                                      └─ iOS: Xcode / Appium
```

## Qué hace

1. Detecta teléfonos/emuladores Android conectados por ADB y simuladores iOS activos.
2. Abre Android mediante scrcpy o trae al frente Simulator para iOS.
3. Mientras haces el recorrido, captura automáticamente cada cambio de pantalla.
   En Android también adjunta actividad, identificadores y estados accesibles de los elementos visibles.
4. Descarga el caso actual desde TestRail y analiza la secuencia con visión.
5. Genera título, precondiciones y pasos separados con resultados esperados.
6. Permite corregir manualmente título, precondiciones y pasos; solo actualiza TestRail después de una confirmación exacta.
7. Crea un respaldo local antes de actualizar y permite restaurarlo desde **Historial**.

Las propuestas expiran en 30 minutos y son de un solo uso. Propuestas y capturas recuperables se guardan localmente y caducan como máximo en una hora. En macOS y Linux viven en `.qa-sync/` del proyecto con permisos `0700`; en Windows `chmod` no puede expresar una ACL, así que el estado vive en `%LOCALAPPDATA%\QA Sync`, donde sólo la cuenta actual puede leerlo. Un `.qa-sync/` existente se sigue usando para no perder datos al actualizar. Para una ubicación administrada puede definirse `QA_SYNC_STATE_DIR`, que tiene prioridad en ambos sistemas. El servidor escucha solo en `127.0.0.1` de forma predeterminada.

## Requisitos

- Python 3.9 o posterior y las dependencias bloqueadas en `requirements.lock`.
- Una sesión iniciada en Codex CLI, Claude CLI o una API key de OpenAI, según la elección personal.
- URL, usuario y API key de TestRail.
- La API de TestRail habilitada en la instancia.
- Para Android: Android Platform Tools (`adb`) y `scrcpy`.
- Para iOS local: macOS con Xcode y al menos un Simulator iniciado. En Windows se admite un Appium remoto ejecutándose en una Mac.
- Para control guiado o iPhone físico: un servidor Appium local con el driver XCUITest y WebDriverAgent correctamente firmado.

Instala las dependencias verificando sus hashes con `python3 -m pip install --require-hashes -r requirements.lock` (Windows: `py -3 -m pip install --require-hashes -r requirements.lock`). `requirements.txt` se conserva como entrada mínima para regenerar el lock.

## Configuración para cada persona

Al abrir QA Sync por primera vez aparece **Configuración personal**. Desde ahí se puede configurar sin editar código:

- Instancia, correo, API key y proyecto preferido de TestRail.
- API key y modelo de OpenAI.
- Proveedor de visión obligatorio: **Codex**, **Claude** u **OpenAI API**. No existe una selección predeterminada.
- Presupuesto explícito de calidad, cantidad y uso: **Eficiente** conserva hasta 8 pantallas representativas con detalle reducido y una llamada; **Alta** analiza todas las pantallas configuradas con detalle alto y una llamada; **Máxima** vuelve a inspeccionarlas en una segunda llamada y consume aproximadamente el doble del límite.
- Límite de pantallas por recorrido.
- Duración máxima por recorrido, entre 60 segundos y una hora.
- Modo **Confirmar y actualizar** o **Sólo simulación**. En simulación el backend rechaza toda escritura aunque se manipule la UI.
- Cambio automático Codex↔Claude únicamente cuando la persona lo autoriza; sólo ocurre ante un límite de uso confirmado.
- System names de pasos, precondiciones y plataforma.
- Valores de plataforma para Android e iOS.
- Perfiles locales por equipo/proyecto. Incluyen proveedor, campos y plataformas, pero nunca credenciales.

En macOS las API keys se guardan en Keychain; en Windows se cifran con DPAPI para el usuario actual. Nunca se devuelven al navegador. En otros sistemas se utiliza un archivo local con permisos `0600`. Los ajustes no secretos viven en `settings.json` dentro del directorio de estado, que está excluido de Git. También puede cambiarse la ubicación con `QA_SYNC_SETTINGS_FILE`.

Codex y Claude reutilizan la sesión iniciada en sus respectivos CLIs y consumen el límite incluido en la cuenta de esa persona. Los procesos son efímeros, reciben únicamente las capturas temporales y no obtienen las API keys de OpenAI, Anthropic o TestRail desde el entorno. Si se agota el límite, la propuesta no se pierde: puede reintentarse con otro proveedor. Para Claude, QA Sync elimina deliberadamente `ANTHROPIC_API_KEY` del proceso para evitar cambiar accidentalmente a facturación de API.

La UI comprueba si cada CLI está instalado y autenticado. Codex y Claude no proporcionan a esta aplicación un porcentaje restante verificable, por lo que se muestra explícitamente **límite restante no expuesto** en vez de estimarlo. El fallback queda desactivado hasta que la persona marque la autorización y elija un proveedor alterno diferente.

Al guardar la configuración, QA Sync consulta `get_case_fields` y comprueba que los campos de pasos, precondiciones y plataforma existan y tengan tipos compatibles.

Las variables de entorno siguen funcionando para despliegues administrados y tienen prioridad sobre secretos guardados. Para configurarlas manualmente:

```sh
cp .env.example .env
```

Edita `.env`. En particular, confirma los nombres reales de los campos personalizados de TestRail. La configuración habitual para casos con pasos separados es:

```dotenv
TESTRAIL_STEPS_FIELD=custom_steps_separated
TESTRAIL_PRECONDITIONS_FIELD=custom_preconds
```

El campo de plataforma es opcional porque sus nombres y valores cambian entre instancias. Si no se configura, el caso igualmente se genera con lenguaje específico para Android o iOS, pero no se modifica ningún campo de plataforma.

### Appium y WebDriverAgent (opcional)

En **Configuración → Visión** agrega la URL local de Appium y el bundle ID de la aplicación. Para un iPhone físico también puedes proporcionar capabilities adicionales en JSON, por ejemplo `appium:xcodeOrgId` o `appium:updatedWDABundleId`. Los campos `automationName`, `udid` y `bundleId` los controla QA Sync y no pueden sobrescribirse.

Cuando Appium está configurado, QA Sync crea una sesión XCUITest para el dispositivo iOS seleccionado. La pantalla aparece dentro del diálogo local: un toque genera `tap`, arrastrar genera `swipe` y el campo inferior envía texto de prueba. El contenido escrito no se guarda en las observaciones. Los screenshots y acciones permanecen en el servidor local.

Las interacciones realizadas directamente sobre el iPhone no pueden ser observadas exactamente por Appium; para obtener pasos determinísticos deben realizarse desde el control guiado de QA Sync. Si Appium no está configurado, los simuladores continúan funcionando mediante captura visual con `simctl`.

### iOS desde Windows

Apple no ofrece Xcode Simulator para Windows. Para probar iOS desde una PC, ejecuta Appium/XCUITest y WebDriverAgent en una Mac accesible mediante HTTPS. En Configuración agrega la URL, bundle ID y la lista **Dispositivos iOS remotos**, por ejemplo:

```json
[{"id":"00008110-...","name":"iPhone QA","version":"18.1"}]
```

El UDID se utiliza únicamente para crear la sesión remota. La Mac sigue siendo responsable del dispositivo, la firma de WebDriverAgent y la captura; TestRail y la UI de QA Sync pueden permanecer en Windows.

## Ejecutar

En macOS puedes abrir **QA Sync.command** con doble clic. Inicia el servidor en segundo plano, abre el navegador y guarda el PID y el log dentro de `.qa-sync/`; `stop-background.sh` lo detiene. No hace falta mantener una terminal abierta.

En Windows abre **QA Sync.cmd**. El lanzador usa PowerShell para iniciar el servidor oculto y abre `http://127.0.0.1:8787`; los logs quedan en el mismo directorio de estado que resuelve `state-dir.ps1`, y el propio servidor publica ahí su `server.pid`. `stop-background.ps1` lo detiene después de comprobar que ese PID sigue siendo un proceso de QA Sync. También puede iniciarse en una consola con:

```powershell
.\run.ps1
```

Windows requiere Python 3, Android Platform Tools y scrcpy en `PATH`. Codex CLI o Claude CLI también deben estar instalados e iniciados en la misma cuenta de Windows si se elige uno de esos proveedores.

También puede iniciarse manualmente:

```sh
chmod +x run.sh
./run.sh
```

Abre [http://127.0.0.1:8787](http://127.0.0.1:8787). Puedes cambiar el puerto con `./run.sh --port 9000`.

## Grabar un recorrido real

1. Elige el proyecto de TestRail y entra a un run activo.
2. Selecciona un TC para ver sus precondiciones y pasos.
3. Presiona **Actualizar**.
4. Elige Android o iOS y el dispositivo donde ejecutarás el recorrido.
5. Presiona **Adelante**. QA Sync abrirá scrcpy o Simulator y comenzará a capturar.
6. Ejecuta manualmente el flujo en la aplicación.
7. Presiona **Finalizar recorrido**.
8. Revisa el diff y los avisos de incertidumbre antes de confirmar la actualización.

Puedes editar el título, las precondiciones, cada acción y su resultado esperado antes de confirmar. Los mismos límites se validan otra vez en el servidor.

En Android, ADB es el transporte de conexión y captura; scrcpy es únicamente la ventana de visualización/control. QA Sync verifica que scrcpy permanezca abierto, informa dispositivos `unauthorized` u `offline` y reintenta tres veces una captura cuando la conexión se interrumpe. El control guiado ADB de la UI registra la acción y conserva pantallas antes y después; las acciones hechas directamente en scrcpy continúan siendo observación best-effort mediante `getevent`.

Desde el mismo diálogo puede conectarse Android mediante Wireless Debugging con una IP privada/local, puerto y código de seis dígitos opcional. También puede declararse el package y un deep link de inicio. **Limpiar datos** requiere indicar el package y confirmar explícitamente la acción; nunca se ejecuta por defecto. La propuesta conserva el presupuesto usado (pantallas recibidas, distintas, analizadas y llamadas), y Android adjunta cuando ADB lo permite modelo, versión/API, resolución, package y versión de la app.

El editor permite agregar, eliminar y reordenar pasos. El estado **Opcional** viaja con el paso al moverlo, para evitar que una reordenación marque otro índice por accidente.

Antes de publicar, cada paso propuesto puede marcarse como **Opcional**. QA Sync lo guarda con el prefijo `[Opcional]` dentro del contenido del paso para funcionar incluso en instancias que no tienen habilitado el campo `additional_info`.

La grabación conserva únicamente pantallas distintas (hasta 16 por recorrido). Antes de enviarlas, vuelve a eliminar capturas consecutivas idénticas y etiqueta explícitamente su orden. Para Android también registra la actividad visible. El análisis compara transiciones, separa cada acción de su resultado observable, aplica reglas específicas de Android/iOS y elimina pasos duplicados. Como las interacciones se infieren visualmente, los gestos o datos que no resulten evidentes se reportan como advertencias en lugar de inventarse.

La calidad **Máxima** ejecuta una segunda revisión visual independiente sobre la propuesta completa para corregir orden, ambigüedad, resultados vacíos, PII y pasos sin evidencia. Si esa revisión adicional falla, se conserva la primera propuesta y se muestra el motivo; nunca se sustituye por contenido parcial. El caso existente y el contexto se acotan por presupuesto total antes de enviarse para evitar gastar uso en contenido repetitivo o desproporcionado.

Usa cuentas y datos de prueba. El analizador sustituye PII, credenciales y datos de clientes por marcadores genéricos, pero la evidencia visual debe prepararse desde el origen para no mostrar información sensible.

## Recuperación y tolerancia a fallas

- Las lecturas de TestRail reintentan errores transitorios y cargan resultados paginados.
- Si visión falla o el proceso se reinicia, las capturas se conservan hasta una hora para reintentar sin repetir el recorrido.
- Las propuestas pendientes también sobreviven un reinicio y reaparecen al abrir la UI.
- Las capturas nuevas se guardan con AES-256-GCM autenticado (`.qasec`). La clave aleatoria vive en Keychain o DPAPI; una captura alterada se rechaza antes del análisis. Las grabaciones antiguas PNG todavía pueden recuperarse para permitir la migración.
- Cancelar una grabación elimina de inmediato sus capturas; un cierre normal detiene y conserva la sesión para recuperación.
- Una grabación se detiene al alcanzar el límite de pantallas o duración y no puede duplicarse sobre el mismo dispositivo.
- Antes de cada actualización se crea un JSON local en `history/` dentro del directorio de estado, con permisos `0600` donde el sistema operativo los admite. El rollback compara primero el estado actual y se bloquea si detecta trabajo posterior de otra persona.
- **Auditoría** exporta un JSON local con identificadores, fechas, estado y nombres de campos modificados; omite el cuerpo de precondiciones/pasos y las credenciales.
- **Matriz** agrega plataforma, dispositivo, versión detectada, casos y última fecha a partir de actualizaciones aplicadas.

La evidencia semántica de Android es best-effort: algunas aplicaciones deshabilitan o esconden su árbol de accesibilidad. En ese caso QA Sync continúa usando las transiciones visuales. En iOS, Appium añade jerarquía XCUITest y captura determinística de taps, swipes y entrada de texto desde el control guiado local.

## Pruebas

```sh
python3 -m unittest discover -s tests -v
```

Las pruebas no llaman a OpenAI ni a TestRail.

`python scripts/ci.py` ejecuta compilación y pruebas con el mismo comando en macOS y Windows. La matriz declarada en `.github/workflows/ci.yml` cubre Python 3.9 y 3.12 en ambos sistemas, pero no se ha publicado ni activado en ningún repositorio remoto.

La suite incluye flujos de integración con dobles de TestRail, proveedores y grabadores. La validación E2E contra una instancia real, un emulador Android y un Simulator iOS requiere credenciales, builds y dispositivos del equipo; no se ejecuta implícitamente para evitar escrituras o instalaciones accidentales.

## Empaquetado para macOS

`packaging/build-pkg.sh` crea `dist/QA-Sync.pkg`. Si `DEVELOPER_ID_INSTALLER` contiene la identidad exacta de un certificado **Developer ID Installer**, firma el paquete y verifica la firma; sin esa identidad produce deliberadamente un paquete sin firma y lo indica en la salida. La notarización y distribución deben añadirse con la cuenta corporativa correspondiente.

## Seguridad y operación

- Consulta [SECURITY.md](SECURITY.md) para el modelo de amenazas, controles y riesgo residual.
- Nunca subas `.env` al repositorio.
- Usa una cuenta de TestRail con el mínimo permiso necesario.
- Revisa los avisos y el diff antes de confirmar.
- Una confirmación inválida consume la propuesta; vuelve a analizar para evitar aplicar un cambio que ya no se revisó.
- QA Sync está diseñado para uso local de una persona; no expongas el puerto a la red.

## Campos enviados a TestRail

- `title`
- El campo configurado en `TESTRAIL_PRECONDITIONS_FIELD`
- El campo configurado en `TESTRAIL_STEPS_FIELD`
- Opcionalmente, el campo configurado en `TESTRAIL_PLATFORM_FIELD`

El resto del caso se conserva sin cambios.

## Revisar la UI sin una instancia real

El repositorio incluye un TestRail simulado exclusivamente para desarrollo visual:

```sh
python3 tests/fake_testrail.py
```

En otra terminal inicia QA Sync apuntando a `http://127.0.0.1:8790`. El servidor simulado nunca debe usarse como configuración de producción.
## Pruebas de seguridad y E2E

La instalación reproducible usa `python -m pip install --require-hashes -r requirements.lock`.
Genera el SBOM con `python scripts/generate_sbom.py --output sbom.cdx.json` y audita el lock con
`uvx pip-audit -r requirements.lock --disable-pip`.

Las pruebas E2E reales son opt-in y nunca actualizan TestRail. Usa exclusivamente un proyecto/caso
de QA dedicado, configura `QA_SYNC_WRITE_MODE=review_only`, `QA_SYNC_E2E=1`,
`QA_SYNC_E2E_CASE_ID` y uno o ambos IDs `QA_SYNC_E2E_ANDROID_DEVICE` /
`QA_SYNC_E2E_IOS_DEVICE`; después ejecuta `python -m unittest tests.test_e2e_live -v`.
