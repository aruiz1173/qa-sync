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

Antes de cada análisis, la persona elige entre ocultar contraseñas/códigos o conservar credenciales de cuentas QA de prueba aisladas. Ocultar es la opción inicial. Si elige conservar, los valores de prueba presentes en texto pueden llegar al proveedor y aparecer en la propuesta, borradores/caché locales cifrados, exportaciones y TestRail si se publica; no se inventan valores. Las claves de API y tokens identificables siguen redactados, incluso con esa opción, y la caché separa ambas políticas. La detección textual no cubre secretos sin etiqueta ni valores visibles en píxeles: la UI exige revisar las pantallas seleccionadas antes de enviarlas a IA. Desmarca cualquier captura que no estés autorizado a compartir.

Codex y Claude reutilizan la sesión iniciada en sus respectivos CLIs y consumen el límite incluido en la cuenta de esa persona. Los procesos son efímeros, reciben únicamente las capturas temporales y no obtienen las API keys de OpenAI, Anthropic o TestRail desde el entorno. Si se agota el límite, la propuesta no se pierde: puede reintentarse con otro proveedor. Para Claude, QA Sync elimina deliberadamente `ANTHROPIC_API_KEY` del proceso para evitar cambiar accidentalmente a facturación de API.

En macOS, una instalación de Android por Homebrew suele vivir bajo una carpeta compartida y QA Sync no ejecuta automáticamente binarios desde ahí. En **Settings → Trusted local tools** se muestra la ruta y SHA-256 de cada candidato y la persona puede aprobar explícitamente ese build; la aprobación es local y queda invalidada al cambiar el binario. Esta misma política se aplica a ejecutables Android sin firma en Windows. `QA_SYNC_TRUSTED_HASHES=adb=<sha256>,emulator=<sha256>,scrcpy=<sha256>` sigue disponible para instalaciones administradas y tiene prioridad sobre las aprobaciones locales.

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

### Execute sin gastar límite de IA

En la app real, abre un run y un TC, pulsa **Execute**, elige el dispositivo y deja marcada **Capture-only: no AI calls during this execution**. Controla la app y marca cada paso manualmente como Pass, Fail, Blocked o Skip optional. En este modo el servidor rechaza Verify with AI, incluso si se intenta por API. Al terminar, deja marcada **Keep this TC's encrypted screenshots and actions for later AI analysis** y pulsa **Finish execution**. La publicación del resultado a TestRail es una opción distinta, desmarcada por defecto; no es necesaria para dejar el TC en cola.

También puedes recorrer el TC desde **Refresh**, detener la captura y pulsar **Save for later · no AI**. Cada TC queda como trabajo local independiente. Abre **AI queue** para revisar sus pantallas y marcar la revisión de datos sensibles; guardar esa selección tampoco llama a IA. Selecciona los TCs revisados y pulsa **Start selected queue · one at a time**. Esta autorización inicia un solo análisis por vez y permanece si reinicias el servidor local. La cola muestra los TCs pendientes en su orden real, el que se analiza, drafts listos, fallos y próximo intento. El refresco de la lista conserva la selección, el foco y el desplazamiento.

**My work** agrupa por TC la evidencia capturada, el estado de la cola y los borradores locales, con una acción para continuar cada trabajo. Durante Refresh, **Save & close** detiene la grabación y conserva sus capturas en la cola local sin llamar a la IA. La comparación de una propuesta muestra lado a lado los campos y pasos originales y editados. Las capturas se muestran como línea de tiempo cronológica; durante la revisión puedes vincular manualmente una captura seleccionada a cada paso. Ese vínculo queda en la propuesta y el draft local, no se envía a TestRail ni significa que la IA haya verificado automáticamente el paso. Si las capturas caducan según la retención configurada, el vínculo permanece pero la imagen deja de estar disponible.

QA Sync recuerda localmente el último proyecto/run y la plataforma, dispositivo y configuración elegidos para cada run o suite compatible. Al regresar, restaura la selección si ese dispositivo sigue conectado; si ya no está disponible, exige escoger otro antes de grabar. No recuerda contexto, deep links, contraseñas ni la opción de borrar datos de la app. El editor muestra cuándo las ediciones están pendientes o guardadas y espera el guardado al cambiar de TC/run; si falla, permanece en el editor. Al restaurar trabajo, **View all work** muestra todos los TCs locales, no sólo el primero destacado en el aviso. La revisión de evidencia permite ampliar pantallas, navegar entre ellas y restaurar o limpiar la selección; antes de analizar se muestra el número aproximado de lotes.

Puedes pausar, reanudar o cancelar los TCs pendientes sin borrar evidencia; un análisis ya iniciado termina antes de parar. Si el proveedor informa que se agotó el límite, el TC actual y los siguientes esperan. Puedes pulsar **Try now** si sabes que el límite ya volvió. El intervalo de reintento (5–120 minutos) y el máximo de respuestas de límite (1–40) se eligen al iniciar y se guardan localmente; al alcanzar el máximo la cola se pausa hasta que la persona la reanude. Un draft guardado antes de una caída se reconoce por una clave estable y no se duplica ni vuelve a llamar a la IA. Los errores distintos al límite marcan sólo ese TC como fallido, pero puedes pulsar **Retry analysis** sin repetir la revisión de las mismas pantallas. La evidencia permanece y nunca se actualiza TestRail automáticamente.

Recuperación ante caída: un frame cifrado y completo que alcanzó disco antes del manifiesto se rescata al reiniciar; un frame parcial o inválido no se usa. Cada lote validado y la síntesis se guardan cifrados por TC y versión de entrada, por lo que el reinicio reutiliza esas respuestas sin otra llamada al proveedor. Si el proceso cae *durante* una llamada, antes de guardar su respuesta, el resultado remoto no puede conocerse: la cola se pausa y exige **Retry analysis** explícito, porque repetir esa llamada podría consumir límite otra vez. Tras guardar un draft, su ID determinístico impide duplicarlo aunque la app caiga antes de marcar el TC como completado. Cambiar capturas, caso, ajustes o prompt invalida los checkpoints incompatibles.

Las capturas cifradas de un TC en cola quedan protegidas de la expiración normal hasta que lo saques de la cola. **Remove** quita sólo el registro de la cola: el draft permanece y la evidencia vuelve a la política normal de retención. La cola guarda metadatos mínimos y contexto textual redactado en el directorio privado de estado. El muestreo periódico tiene los límites de captura configurados; Execute adjunta además checkpoints por paso cuando están disponibles. Si el dispositivo o la captura falla, revisa las advertencias antes de confiar en una propuesta posterior.

Para presentaciones abre **Guided tour · demo** desde la columna Runs o visita `http://127.0.0.1:8787/demo.html`. Usa cuatro runs y 20 TCs ficticios del fixture local: no consulta TestRail, no controla dispositivos, no ejecuta casos y no llama a IA. Los estados Pass/Fail son etiquetas ilustrativas, no resultados obtenidos. El tour explica la navegación, la lectura de un TC, la selección *de ejemplo* de evidencia, una sugerencia preescrita, revisión por paso, edición, draft y métricas limitadas a la pestaña. Los nombres de pantallas no son capturas; la sugerencia no se deriva de ellos y no se procesan lotes. **Execute** está disponible sólo como simulación aparte, iniciada por el usuario; el tour no entra ahí. Los cambios y decisiones de la demo no escriben en TestRail. Para probar los flujos reales hay que volver al workspace principal y configurar TestRail, dispositivo y proveedor por separado.

En macOS puedes abrir **QA Sync.command** con doble clic. Registra el servidor en la sesión del usuario mediante `launchd`, espera a que responda y abre el navegador. El servidor sobrevive al cierre del lanzador o de Codex; `stop-background.sh` lo detiene mediante `launchd`. El agente queda en `~/Library/LaunchAgents/com.qasync.local.plist` y los logs en `~/Library/Logs/QA Sync/`. Como macOS no permite al servicio en segundo plano importar la app desde `Downloads`, el lanzador crea una copia privada del código y del `.env` en `~/Library/Application Support/QA Sync/runtimes/`. La primera vez copia también el estado local (borradores, ajustes y propuestas) a `~/Library/Application Support/QA Sync/`, dejando intacta la carpeta anterior; a partir de entonces el arranque manual usa ese mismo estado. La copia se actualiza cuando cambia el código o el `.env`. Si ya había un servidor iniciado manualmente, el lanzador lo abre pero avisa que todavía no está bajo `launchd`; detenlo primero y vuelve a abrir **QA Sync.command** para transferirlo al lanzador.

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

Un análisis exactamente idéntico puede reutilizarse durante 24 horas sin consumir otra llamada de visión. La huella incluye capturas, contenido actual del caso, referencias de estilo, contexto, reglas, template, plataforma, campos, proveedor, fallback, modelo y calidad. El resultado se cifra con AES-256-GCM, se limita a 100 entradas y se invalida ante cualquier cambio. Antes de finalizar un recorrido puede marcarse **Ignore an identical cached result** para forzar un análisis nuevo.

Usa cuentas y datos de prueba. El analizador sustituye PII, credenciales y datos de clientes por marcadores genéricos, pero la evidencia visual debe prepararse desde el origen para no mostrar información sensible.

## Ejecutar y verificar un caso

Desde un caso dentro de un run, **Execute** abre el ejecutor determinístico. Android usa el control guiado de ADB; iOS exige Appium/XCUITest porque las acciones hechas directamente en Simulator no pueden atribuirse de forma determinística.

Antes de cada paso se guarda un baseline cifrado. Después de realizar la acción, **Verify with AI** espera hasta que dos observaciones consecutivas —screenshot y árbol accesible— sean iguales, con un timeout de seguridad, y compara explícitamente el estado anterior con el posterior. Sólo un cambio visible, estable y con confianza igual o mayor al umbral configurado puede cerrarse automáticamente; una pantalla que no se estabiliza o una observación ambigua queda en **needs review**. La persona puede revisar o reemplazar cualquier veredicto de IA. Los pasos Failed y Blocked exigen un motivo, y únicamente los pasos marcados `[Optional]` se pueden omitir.

Al terminar se calcula Passed, Failed o Blocked. Publicarlo en TestRail es opcional y requiere escribir `PUBLICAR T<id del test>`; no basta con el número del caso. Si la conexión se corta durante `add_result`, QA Sync marca la publicación como desconocida y no la reintenta automáticamente, evitando resultados duplicados.

## Recuperación y tolerancia a fallas

- Las lecturas de TestRail reintentan errores transitorios y cargan resultados paginados.
- Si visión falla o el proceso se reinicia, las capturas se conservan hasta una hora para reintentar sin repetir el recorrido.
- Las propuestas pendientes también sobreviven un reinicio y reaparecen al abrir la UI.
- Las capturas nuevas se guardan con AES-256-GCM autenticado (`.qasec`). La clave aleatoria vive en Keychain o DPAPI; una captura alterada se rechaza antes del análisis. Las grabaciones antiguas PNG todavía pueden recuperarse para permitir la migración.
- Cancelar una grabación elimina de inmediato sus capturas; un cierre normal detiene y conserva la sesión para recuperación.
- Una grabación se detiene al alcanzar el límite de pantallas o duración y no puede duplicarse sobre el mismo dispositivo.
- Antes de cada actualización se crea un JSON local en `history/` dentro del directorio de estado, con permisos `0600` donde el sistema operativo los admite. El rollback compara primero el estado actual y se bloquea si detecta trabajo posterior de otra persona.
- **Auditoría** exporta un JSON local con identificadores, fechas, estado y nombres de campos modificados; omite el cuerpo de precondiciones/pasos y las credenciales.
- **Preflight → Download support report** descarga un diagnóstico local separado para soporte: estado de readiness, runtime, capacidades y errores de herramientas. No contiene credenciales, capturas, pasos, cuerpos de casos ni registros de auditoría. Revísalo antes de compartirlo fuera del equipo.
- **Matriz** agrega plataforma, dispositivo, versión detectada, casos y última fecha a partir de actualizaciones aplicadas.

La evidencia semántica de Android es best-effort: algunas aplicaciones deshabilitan o esconden su árbol de accesibilidad. En ese caso QA Sync continúa usando las transiciones visuales. En iOS, Appium añade jerarquía XCUITest y captura determinística de taps, swipes y entrada de texto desde el control guiado local.

## Pruebas

```sh
python3 -m unittest discover -s tests -v
```

Las pruebas no llaman a OpenAI ni a TestRail.

`python scripts/ci.py` ejecuta compilación y pruebas con el mismo comando en macOS y Windows. La matriz declarada en `.github/workflows/ci.yml` cubre Python 3.9 y 3.12 en ambos sistemas, pero no se ha publicado ni activado en ningún repositorio remoto.

La suite incluye flujos de integración con dobles de TestRail, proveedores y grabadores. La validación E2E contra una instancia real, un emulador Android y un Simulator iOS requiere credenciales, builds y dispositivos del equipo; no se ejecuta implícitamente para evitar escrituras o instalaciones accidentales.

Para el smoke E2E dedicado usa sólo un caso de sandbox. Define `QA_SYNC_E2E_CASE_ID`, el dispositivo Android y/o iOS dedicado, y confirma el destino con `QA_SYNC_E2E_CONFIRM_SANDBOX=yes`. Los lanzadores `run-e2e.sh` (macOS/Linux) y `run-e2e.ps1` (Windows) fuerzan `QA_SYNC_WRITE_MODE=review_only`; si falta la confirmación se detienen sin contactar TestRail.

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
