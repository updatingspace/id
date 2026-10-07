# UpdSpace ID: Rust workspace

Это ещё не завершённая миграция. **Проверка production Gateway 7 октября
2026 года подтвердила 121 интеграцию только с четырьмя Rust-контейнерами:
основной API, мутации, чтение сессий и Topcoat web. Старый React fallback
отключён; неизвестные страницы возвращают 404.** Это подтверждает
маршрутизацию, но не функциональный паритет всех операций. Исполняемый Python
и React удалены из актуального проекта; Rust сохраняет адаптеры к действующим
форматам credentials и данным. `ID CI/CD` проверяет Rust/YDB/Topcoat,
инфраструктуру и обязательный расширенный набор интеграционных сценариев на
локальной YDB. Production admin пока не включён, а отложенная
выгрузка остаётся локальным пилотом. Открытые условия описаны в
[контракте интерфейса и экспорта](../../docs/rust-migration/identity-ux-and-export.md).

## Состав

`id-web` — отдельный Topcoat SSR-сервис и область работы над интерфейсом.
Маршруты страниц здесь получают данные через типизированные структуры ответов
`id-api` и собирают HTML на сервере; небольшой браузерный JS нужен для форм,
WebAuthn и других интерактивных действий. Веб-сервис не открывает YDB и не
получает ключи подписи. Например, `crates/id-web/src/account.rs` содержит
разметку кабинета, а `crates/id-web/src/account/api.rs` — его HTTP-клиент и
структуры ответов. `id-runtime`/`id-api` остаются областью auth, данных и
публичных API-контрактов. Маршрутизатор Topcoat выбирает страницу для SSR;
он не заменяет маршрутизатор API и сам по себе не является всей реализацией UI.

- `id-compat`: проверка Argon2, BCrypt-SHA256 и PBKDF2-SHA256 в форматах Django;
  чтение/запись JSON SessionStore с zlib, ротацией ключей и session auth hash;
  приоритет заголовков, сравнение CSRF, TOTP и recovery codes allauth, внутренний HMAC
  и переносимые значения временного YDB-кэша.
- `id-runtime`: общий YDB-клиент с явным выбором credentials, TLS и timeout.
  Read-only `me_store` проверяет существующую Django session, account, metadata,
  неизменяемый identity binding, статус master identity и отсутствие
  незавершённого удаления, затем читает профиль в той же транзакции YDB.
  Для `/me` аккаунт с MFA принимается только с подписанным session marker,
  привязанным к Django user ID. Переходный Python пишет marker после успешного
  headless-входа с TOTP/recovery code. Старые и другие allauth/passkey/social
  сессии без доказуемого marker пока не проходят этот маршрут; нужна сверка
  действующих сессий и проверка всех межверсионных сценариев до canary.
  `cache_store` читает, атомарно добавляет/увеличивает счётчики и потребляет
  новый формат кэша в YDB;
  legacy pickle должен быть перекодирован перед переключением.
  `id-api` по умолчанию публикует только `/healthz` и `/readyz`. Пилотная
  `/api/v1/auth/me` включается явно через `ID_AUTH_ME_ENABLED=true` и требует
  `DJANGO_SECRET_KEY`. При `S3_QUERYSTRING_AUTH=true` `/me`, login и OIDC UserInfo
  формируют ограниченные по времени URL приватных аватаров через S3 SigV4.
  Подпись сверена с эталонным вектором AWS; реальный GET из production Object
  Storage ещё не проверен.
  `/api/v1/auth/form_token` включается отдельно через
  `ID_AUTH_FORM_TOKEN_ENABLED=true`: выдаёт одноразовый токен в общем YDB-кэше
  (`YDB_CACHE_TABLE`, по умолчанию `id_shared_cache`) и читаемый CSRF cookie.
  Переходный Python и Rust способны взаимно потребить такой токен ровно один раз.
  Rust также атомарно обновляет общий с Python login rate-limit budget в YDB;
  100 одновременных обновлений через два SDK-клиента не потеряли счётчики.
  Локальный HTTP login уже использует этот бюджет; для production остаются
  Gateway/CORS-проверки и квалификация поведения при отказах.
  `login_preflight` уже проверяет существующий парольный хеш вне async executor
  через ограниченный blocking pool, а также email verification, MFA, immutable
  identity, статус и удаление в одном YDB-снимке. Он пока не выпускает сессию.
  `auth_user.email` не индексирован. Переходный Python поддерживает
  `accounts_accountemaillookup`; Rust ищет по синхронному индексу и повторно
  сверяет исходный адрес. N-1 backfill и проверка целостности прошли на
  локальной YDB; production-данные и все writers ещё не квалифицированы.
  `session_issuer` повторно проверяет аккаунт без MFA и атомарно записывает
  Django session, allauth UserSession, revocation metadata, last_login и
  SimpleJWT outstanding/session-token mapping. Сессия и пара account JWT
  выдаются только после подтверждённого commit. Python на локальной YDB
  восстановил сессию, принял Rust refresh и выполнил rotation.
  Отдельный `POST /api/v1/auth/jwt/from_session` включается через
  `ID_AUTH_JWT_SESSION_PILOT_ENABLED=true` при debug + YDB `/local` либо при
  явном `ID_RUST_EARLY_ROLLOUT_ENABLED=true`. Он заново
  проверяет session/identity/MFA, атомарно сохраняет привязанный refresh и
  выдаёт пару только после commit; browser cookie требует CSRF, а явный
  session header имеет приоритет. `POST /api/v1/auth/refresh` включается
  тем же флагом: Rust проверяет HS256-подпись и outstanding-token,
  в одной YDB-транзакции погашает старый refresh и выдаёт новый. Подтверждённый
  replay закрывает всю связанную сессию и её descendants. Production-проверка
  Rust → Python → Rust и публичный smoke через Gateway прошли на выделенном
  тестовом аккаунте; нагрузка и аудит остальных действующих credentials ещё нужны.
  Локальный `POST /api/v1/auth/account/deletions` включается отдельно через
  `ID_AUTH_DELETION_PILOT_ENABLED=true` при debug + YDB `/local` и требует
  `ID_DELETION_OPERATION_KEY`. После проверки текущего пароля и MFA он
  транзакционно записывает `pending`, блокирует account/identity и отзывает
  сессии, account JWT и OIDC-доступ. `Idempotency-Key` обязателен; повтор с
  тем же ключом и прежней сессией возвращает ту же операцию даже после отзыва.
  Первый шаг очистки доступен оператору через
  `idctl deletion-erase-credentials <id> --apply`: он повторяемо стирает
  основные MFA/passkeys, OIDC, account и master-identity login credentials
  только после подтверждения отключения аккаунта и identity. Статус становится
  `running`. Команда без `--apply` только читает состояние. Социальные токены,
  email-ссылки и дочерние записи blacklist также стираются до своих родителей.
  Приватный timer `id-jobs /internal/jobs/recover` подбирает `pending` заявки
  пачками до 10; ошибки одной заявки возвращаются как deferred и не мешают
  обработке следующих. Второй этап удаляет аватар из Object Storage подписанным
  S3-запросом и только после ответа 204 очищает его ключ в YDB; метка
  `avatar_done` предотвращает повторный обход завершённых операций. Для
  локальной media storage и версионированных S3 buckets этот этап пока не
  подтверждён. Третий этап после `avatar_done` удаляет профиль, историю,
  настройки, согласия, адреса и связанные mail/session records; `profile_done`
  записывается в той же транзакции. `auth_user`, identity binding, session
  metadata и глобальные audit/outbox records требуют финальной сверки.
  Финализатор проверяет пустоту legacy application и отсутствие
  известных дочерних записей, затем одной транзакцией удаляет account,
  binding, существующую master identity и session metadata, оставляя
  обезличенный receipt со статусом `succeeded`. Для заявок с master identity
  необходим `idctl legacy-cutover-seal --apply` и чистый адресный UUID-проход
  по audit/outbox: события других пользователей после seal не удерживают
  заявку. Старые заявки с пустым
  `identity_id` могут завершиться до seal только для уже отключённого аккаунта
  и при пустых глобальных legacy-таблицах. Этот путь проверен локальным YDB и
  выполнен для двух одобренных production-заявок; постоянный timer не включён.
  `idctl deletion-erase-avatar <id> --apply` повторяет один этап без доступа к
  медиа и отказывает, если у профиля ещё есть ключ объекта.
  `idctl deletion-erase-profile <id> --apply` адресно очищает профиль и историю;
  `idctl deletion-complete-global <id> --apply` подтверждает отдельным чистым
  проходом отсутствие ссылок в глобальных записях. Оба режима без `--apply`
  только читают статус/audit и не затрагивают другие заявки.
  `idctl deletion-status <id>`
  не выводит owner или причину удаления.
  Разрушающие тесты `legacy_cutover_reset_ydb` и
  `data_export_delete_flow_ydb` запускаются только с
  `ID_DISPOSABLE_YDB=true` на отдельной локальной YDB с `GRPC_PORT=2137`;
  проброса host `2137` на container `2136` недостаточно: SDK discovery может
  направить последующие запросы в базу на `2136`. CI поднимает и удаляет
  отдельный контейнер для этого теста.
  Внутренний `data_export` выводит NDJSON порциями по 128 строк, потоковые
  base64-части аватара с SHA-256 и manifest без password/MFA/bearer credentials.
  Локальный YDB-тест выгрузил 205 согласий и 105 событий входа без прежних
  лимитов и без данных другого аккаунта; отдельно восстановил байты аватара.
  `idctl data-export-schema` создаёт отдельную durable operation с owner,
  идемпотентным HMAC ID, due-index, lease и fencing token. Два клиента локальной
  YDB выдержали 100 конкурентных claim: ровно один выиграл; после истечения
  lease старый worker не может завершить новую попытку.
  `idctl data-export-escrow-schema` создаёт отдельную таблицу для будущей
  отложенной выдачи после удаления аккаунта. Локальный pilot записывает запрос
  и зашифрованный подтверждённый адрес в одной транзакции, сохраняет снимок
  отдельно от префикса владельца и задерживает очистку профиля до его
  завершения. `idctl data-export-mail-schema` создаёт outbox для уведомления
  и письма после 24 часов. Локальный SMTP-тест проверяет обе доставки;
  отдельная Topcoat-страница передаёт capability в API телом POST и получает
  краткоживущую ссылку без сессии аккаунта. Отдельная локальная job очищает
  просроченный escrow-объект и адрес доставки после подтверждённого удаления
  из S3. Production-флаги для задержки, почты и страницы существуют отдельно,
  но пока выключены: реальный Object Storage и timer HTTP trigger ещё не
  прошли сквозную проверку вместе. Отдельный синтетический smoke с действующим
  production bucket подтвердил upload, signed GET, delete и последующий 404
  для owner- и escrow-префиксов без пользовательских данных. Команда теперь
  также сверяет точный список объектов уникального escrow-префикса до и после
  удаления; этот новый шаг на production bucket ещё не выполнялся. Дополнительный
  opt-in прогон `ID_EXPORT_TEST_REAL_S3=true` использовал локальную одноразовую
  YDB, настоящий production Object Storage и локальный SMTP: синтетический архив
  был создан после отзыва доступа, скачан после удаления аккаунта и удалён из
  bucket с подтверждённым 404. В изолированной YDB
  на порту 2137 тест
  `data_export_delete_flow_ydb` уже проходит HTTP-запросы, настоящий приватный
  HTTP-таймер `id-jobs` для снимка и двух писем через локальный SMTP, Rust stages,
  финализацию аккаунта после cutover seal, 24-часовую выдачу письма и
  скачивание после физического удаления аккаунта и identity.
  Локальный pilot теперь
  загружает NDJSON в приватный S3 через ограниченный по памяти multipart,
  обслуживает owner-scoped status/download с 60-секундной ссылкой и удаляет
  подтверждённый архив через 24 часа или при удалении аккаунта. При удалении
  worker ждёт окончания активной аренды экспорта, сверяет S3-префикс владельца,
  удаляет также объекты без записи о завершении в YDB и отдельным проходом
  подтверждает пустой префикс. До включения задержанной выдачи остаётся
  сквозная проверка такого прохода на настоящем Yandex Object Storage,
  включая freeze/resume. Локальный HTTP
  pilot включается только через `ID_EXPORT_API_PILOT_ENABLED=true` при
  `DJANGO_DEBUG=true` и YDB `/local`. Отдельный production-флаг
  `ID_EXPORT_API_ROLLOUT_ENABLED=true` требует общего разрешения Rust rollout;
  Terraform создаёт приватный bucket и постоянный HMAC-ключ операции только при
  `enable_rust_export=true`; HTTP API включается отдельным
  `enable_rust_export_api=true`. Приватный production bucket, lifecycle,
  YDB-схема и синтетическая запись/чтение/удаление через действующие S3
  credentials проверены. Немедленный экспорт работает в production; задержанный
  экспорт, его выдача по почте после удаления аккаунта и соответствующая
  Topcoat-страница в production не включены. Сквозной сценарий через Gateway
  для задержанной выдачи ещё не проверен.
  `POST /api/v1/auth/login` включается через
  `ID_AUTH_LOGIN_PILOT_ENABLED=true`; вне локального debug/YDB `/local`
  дополнительно требуется `ID_RUST_EARLY_ROLLOUT_ENABLED=true`. По проверке
  Gateway 7 октября production направляет публичный POST в Rust API; прежняя
  заметка о Python-маршруте относилась к переходному пилоту. Обработчик
  проверяет JSON, Origin/CSRF, одноразовый form-token и общий login rate-limit;
  после preflight выдаёт cookie/session/JWT. TOTP и recovery code проверяются
  и потребляются в транзакции выдачи; некорректный MFA не выдаёт credentials.
  Переходный Axum→YDB→Python тест прошёл до удаления Python runtime. В той же транзакции Rust записывает
  историю входа, устройство и outbox уведомления о новом устройстве.
  `POST /api/v1/auth/logout` включается отдельно через локальный
  `ID_AUTH_LOGOUT_PILOT_ENABLED=true` при `DJANGO_DEBUG=true` и YDB `/local`
  либо через production-пару `ID_AUTH_LOGOUT_ROLLOUT_ENABLED=true` и
  `ID_RUST_EARLY_ROLLOUT_ENABLED=true`.
  Заголовок сессии имеет приоритет над cookie; браузерный запрос требует CSRF.
  Отзыв текущей Django-сессии, metadata, UserSession и связанного account
  refresh выполняется в одной YDB-транзакции. Проверка на локальной YDB
  подтверждает, что выбранная сессия и её действующий refresh отозваны,
  а другая сессия сохранена.
  В production маршрут открывается только после отдельной проверки
  HTTP/Gateway и межверсионных сценариев на тестовых credentials.
  `GET /api/v1/auth/sessions` включается отдельно через
  `ID_AUTH_SESSIONS_READ_ENABLED=true` вместе с
  `ID_RUST_EARLY_ROLLOUT_ENABLED=true`; локальный
  `ID_AUTH_SESSIONS_PILOT_ENABLED=true` также включает чтение и мутации.
  Читает allauth и revocation metadata по индексам, одним запросом получает
  сроки Django-сессий и обновляет активность текущей сессии. Локальный
  Axum→YDB→Python тест сравнивает весь JSON с `SessionService.list` до и после
  отзыва; два конкурентных запроса к legacy-сессии без metadata создают ровно
  одну запись каждого типа. В production read-only GET/OPTIONS направлены
  Gateway в отдельный Rust-контейнер и проверены с действующей сессией;
  нагрузочные замеры на длинной истории сессий ещё нужны.
  Локальный флаг либо production-пара
  `ID_AUTH_SESSIONS_MUTATIONS_ROLLOUT_ENABLED=true` и
  `ID_RUST_EARLY_ROLLOUT_ENABLED=true` открывают
  `DELETE /api/v1/auth/sessions/{sid}`,
  `POST /api/v1/auth/sessions/bulk` и alias `/_bulk`. Цели выбираются только
  среди сессий владельца; metadata, Django-сессия и account refresh меняются
  в одной транзакции YDB. Browser mutations требуют CSRF, а самоотзыв очищает
  cookie. Интеграционный тест проверяет single, оба bulk-варианта, чужой и
  отсутствующий ID, сохранение текущего устройства и отказ Python принимать
  каждый отозванный refresh. Mutation-маршруты обновляют активность текущей
  сессии в той же транзакции, включая создание отсутствующих legacy-записей.
  Для bulk сверены ошибки пустого и битого body, неверных типов полей и
  совместимость JSON при `text/plain`. Production Gateway направляет эти
  mutation-маршруты в отдельный Rust-контейнер; проверены CSRF, явный неверный
  токен, single, bulk, alias, отзыв refresh и Chromium. Для полноценной
  приёмки остаются гонки на двух экземплярах и p95 на длинной истории сессий.
  `PATCH /api/v1/auth/profile` включается отдельно через локальный
  `ID_AUTH_PROFILE_PILOT_ENABLED=true` при debug + YDB `/local` либо через
  production-пару `ID_AUTH_PROFILE_ROLLOUT_ENABLED=true` и
  `ID_RUST_EARLY_ROLLOUT_ENABLED=true`. В одной
  serializable-транзакции повторно проверяет session/identity/MFA и меняет
  имя, телефон и дату рождения. Создание отсутствующего профиля проверено
  на `BigSerial`; 20 конкурентных запросов оставили ровно одну строку.
  Контрактный тест включает CSRF, приоритет заголовка и неверную дату.
  В production точный PATCH/OPTIONS-маршрут проверен на выделенном аккаунте:
  запрет без CSRF и при неверном заголовочном токене, изменение через Rust,
  чтение через `/me`, восстановление исходного имени и Topcoat SSR reload.
  Локальный `ID_AUTH_PREFERENCES_PILOT_ENABLED=true` либо production-пара
  `ID_AUTH_PREFERENCES_ROLLOUT_ENABLED=true` и
  `ID_RUST_EARLY_ROLLOUT_ENABLED=true` открывают GET/PATCH предпочтений,
  каталог часовых поясов и список/отзыв согласий. Язык, зона, маркетинговый
  флаг, политики и audit записываются в одной YDB-транзакции; 20 конкурентных
  первых GET оставили одну строку. Список из 433 зон соответствует текущему
  переходному `pytz.common_timezones`, смещения рассчитывает `chrono-tz`.
  В production ответы GET на выделенном аккаунте сверены с Python,
  проверены CSRF, приоритет заголовка, изменение/возврат настроек и отзыв
  маркетингового согласия. Остальные mail effects и нагрузочная приёмка
  остаются открытыми.
  Readiness здесь проверяет запрос YDB, **не готовность identity-функций**.
- `idctl`: read-only `ydb-probe`, `cache-audit`, `mfa-session-audit`,
  `login-email-audit` и отчёт `inventory`, синтетический
  `compat-fixtures` для проверки записей Rust установленным Django.
  `smoke-exchange` создаёт краткоживущий синтетический код в общем YDB-кэше,
  проверяет подписанный обмен и отказ на повтор через HTTPS Gateway, затем
  удаляет тестовый ключ. Команде нужны `BFF_INTERNAL_HMAC_SECRET` и доступ к
  YDB; секрет и сам код не выводятся в отчёт.
  `cleanup-tokens` по умолчанию считает устаревшие activation, magic-link и
  OAuth-state токены; `--execute` удаляет их с повторной проверкой в YDB.
  `cache-schema` повторяемо создаёт и проверяет общий YDB-кэш для одноразовых
  credentials и rate limits, без Python. `legacy-schema` проверяет 50 переходных
  таблиц и 98 индексов; `--apply`
  повторяемо создаёт отсутствующие объекты только в локальном YDB.
  `legacy-ledger --apply` после проверок identity и email записывает четыре
  исторические версии без Python; запись пока ограничена локальным YDB.
  `identity-reconcile` по умолчанию только классифицирует аккаунты. После
  `login-email-reconcile` его `--apply` на локальном YDB создаёт master и
  binding в одной транзакции только для активных аккаунтов с подтверждённым
  основным email. Старый `public_subject` сохраняется; связь с существующим
  master **не выводится из совпавшего email**.
  Аккаунты с прежними OIDC-токенами без binding, совпавшим master email и
  неподтверждённым email, отключёнными аккаунтами и повреждёнными связями
  учитываются в `needs_review`, без записи данных.
  Старые writers должны быть остановлены до применения. Production-применение
  остаётся заблокированным до сверки реальных данных и квалификации команды.
  `login-email-reconcile` делает dry-run по умолчанию; `--apply` транзакционно
  восстанавливает derived email lookup и удаляет осиротевшие ключи, затем
  требует успешный audit без коллизий.
  При `ID_AUTH_PREFERENCES_PILOT_ENABLED=true` Rust API также отдаёт
  `/api/v1/auth/consents` и `/api/v1/auth/consents/revoke`. Отзыв маркетингового
  согласия атомарно выключает `marketing_opt_in` и записывает audit; обязательное
  согласие на обработку данных этим маршрутом не отзывается. Локальный тест
  проверяет конкурентный повтор отзыва. Включение/выключение маркетинговой
  настройки синхронизирует ledger согласий в той же транзакции. При
  `ID_WEB_CONSENTS_PILOT_ENABLED=true`
  Topcoat показывает историю и кнопку отзыва в разделе приватности.
- `id-web`: отдельный crate Topcoat 0.9.0 с буферизованным SSR. При
  `ID_WEB_LOGIN_PILOT_ENABLED=true` отдаёт `/login` и локальные CSS/JS. Страница
  обращается к `/api/v1/auth/form_token` и `/api/v1/auth/login` через тот же
  origin, поддерживает пароль, TOTP и резервный код, сохраняет только HttpOnly
  session cookie от API и проверяет локальный `next`. Для локального браузерного
  прогона нужен Gateway/reverse proxy, совмещающий UI и API под одним origin.
  `ID_WEB_PASSKEY_PILOT_ENABLED=true` добавляет вход по WebAuthn через Rust API;
  отдельный браузерный прогон `scripts/smoke-web-passkey-live.sh` связывает
  Topcoat, Axum, YDB и `/me` с синтетическим подписанным ключом.
  При `ID_WEB_ACCOUNT_PILOT_ENABLED=true` и обязательном `ID_WEB_API_ORIGIN`
  Topcoat отдаёт `/account`: сервер пересылает browser cookie на Rust `/me`,
  перенаправляет гостя на `/login` и рендерит профиль, настройки, устройства и
  доступные разделы безопасности. При `ID_WEB_PROFILE_PILOT_ENABLED=true`
  страница также управляет аватаром через Rust `POST/DELETE /api/v1/auth/avatar`;
  CSP разрешает изображения только с собственного origin, `data:` и точного
  Yandex Object Storage origin. API origin должен быть HTTPS (либо localhost
  HTTP для теста). Ссылка на `/legacy/account` удалена из Topcoat: React-код
  больше не входит в актуальную сборку, а недостающие функции кабинета остаются
  открытыми задачами. Ядро и `idctl` не зависят от Topcoat. Cookie jar,
  альтернативной системы сессий, SSE и доступа UI к YDB нет.
  `ID_WEB_EXPORTS_ENABLED=true` отдельно добавляет `/account?section=data`:
  Topcoat на сервере загружает owner-scoped состояние операции и manifest,
  рендерит состав архива, ожидание или ссылку на скачивание. Небольшой JS только
  отправляет пароль, MFA и запрос на создание с сохраняемым `Idempotency-Key`, после чего
  браузер переходит на SSR-страницу статуса. Флаг остаётся выключенным до
  production-проверок Rust API, приватного хранилища и jobs.
  Сквозной browser→Topcoat→same-origin proxy→Rust API→YDB smoke вынесен в
  `scripts/check-web-login-live.cjs`. Для него нужны работающий стенд, отдельный
  тестовый аккаунт и Playwright/Chromium; адрес, учётные данные и пути передаются
  через `ID_LIVE_BASE_URL`, `ID_LIVE_EMAIL`, `ID_LIVE_PASSWORD`,
  `ID_PLAYWRIGHT_MODULE` и при необходимости `ID_CHROMIUM_PATH`. При
  `ID_LIVE_ACCOUNT_SSR=true` smoke дополнительно проверяет гостевой редирект и
  SSR профиля. Для локальной YDB перед smoke выполните `idctl cache-schema`:
  Django `migrate_ydb` общую таблицу кэша не создаёт.
  Topcoat `/login` также переводит действующий старый `id_session_token` из
  sessionStorage в HttpOnly cookie через Rust `/me` при возврате с защищённого
  маршрута. Сначала проверяется существующая cookie; после проверки явного
  токена UI отдельно подтверждает, что cookie действительно работает, и только
  затем удаляет токен. Сценарии проверяет
  `scripts/check-web-legacy-bridge-live.cjs` на локальной YDB.
  При `ID_WEB_SESSIONS_PILOT_ENABLED=true` появляется SSR-раздел
  `/account?section=sessions`: `id-web` запрашивает Rust `/sessions` с browser
  cookie, а небольшой JS-слой завершает отдельную либо все другие сессии с CSRF.
  В production чтение и отзыв сессий обслуживают разные Rust-контейнеры.
  Многосессионный Chromium smoke —
  `scripts/check-web-sessions-live.cjs` с теми же переменными окружения.
  При `ID_WEB_LOGOUT_PILOT_ENABLED=true` оба SSR-раздела показывают «Выйти».
  Браузер отправляет cookie и CSRF в Rust `/logout`, затем подтверждает гостевой
  ответ `/me` и очищает старый token из sessionStorage. Отдельный Chromium
  smoke — `scripts/check-web-logout-live.cjs`.
  При `ID_WEB_PROFILE_PILOT_ENABLED=true` SSR-профиль показывает форму имени,
  телефона и даты рождения, отправляющую same-origin `PATCH /profile` с CSRF.
  HTTP smoke проверяет SSR, CSP и гостевой редирект. Chromium E2E на локальной
  YDB через `scripts/check-web-profile-live.cjs` подтвердил сохранение и
  повторную загрузку, включая отказ без CSRF. Gateway, Firefox/WebKit и
  остальные разделы кабинета требуют отдельной проверки через production Gateway.
  При `ID_WEB_PREFERENCES_PILOT_ENABLED=true` появляется
  `/account?section=privacy`: SSR-загрузка настроек и зон, форма с CSRF и
  same-origin PATCH. Chromium E2E на локальной YDB и production проверил
  сохранение, reload и восстановление исходных значений. При
  `ID_WEB_CONSENTS_PILOT_ENABLED=true` раздел также показывает историю
  согласий и отзыв маркетингового согласия через Rust API.
  При `ID_AUTH_APPS_PILOT_ENABLED=true` и `ID_WEB_APPS_PILOT_ENABLED=true`
  локальные Rust API и Topcoat показывают remembered OIDC-приложения и дают
  отозвать выбранный грант. Отзыв объединяет consent, токены, ожидающие codes и
  requests в одной YDB-транзакции; реальная локальная YDB и Chromium прошли
  проверку. Production-включение запрещено до переноса OIDC выдачи и проверки
  гонок выдачи против отзыва. Детали —
  [в отчёте](../../docs/rust-migration/verification-2026-10-04-oauth-apps.md).
  `POST /oauth/token` с `grant_type=authorization_code`, `POST /oauth/revoke`,
  `GET/POST /oauth/userinfo`, discovery по
  `/.well-known/openid-configuration` и JWKS по
  `/oauth/jwks`, `/.well-known/jwks.json` включаются только через
  `ID_OIDC_TOKEN_PILOT_ENABLED=true` при debug и локальной YDB. Он принимает
  прежние authorization codes, проверяет exact redirect и PKCE S256, активный
  identity binding, атомарно потребляет code и подписывает access/ID JWT
  существующим RS256 keyset без генерации нового ключа. `sub` и `user_id`
  остаются стабильными. 25 конкурентных обменов на локальной YDB дали ровно
  одну выдачу; отключённый аккаунт отклонён.
  Дублирующийся `client_id` блокирует authorize, ожидающее consent,
  code/refresh exchange и revoke: идентификатор клиента должен однозначно
  соответствовать одной записи и при выдаче, и при commit.
  Расширенные scopes `phone`, `address`, `profile_extended` выдаются только
  после проверки разрешений клиента и согласия пользователя; claims проверены
  на локальной YDB. `offline_access` выдаёт opaque refresh в новом
  семействе. Rust и переходная Python-версия атомарно ротируют refresh,
  допускают сужение scope и отзывают активных потомков при replay. Проверена
  гонка 100 запросов на локальной YDB: одна выдача, потомок отозван.
  JWKS включает активный и прежние public keys с прежними `kid`; оба HTTP-пути
  и проверка JWT через опубликованные `n`/`e` проверены локально. Discovery
  указывает действующие адреса, но публикует только scopes, для которых Rust
  уже выдаёт claims. UserInfo
  повторно сверяет подписанный JWT, действующий токен, отзыв, клиента, scope,
  активный identity и subject. Локальная YDB подтвердила отказ после revoke и
  disable, выдачу полей для email, профиля, телефона и address. Для аватара
  требуется `MEDIA_PUBLIC_BASE_URL`; приватные подписанные URL ещё не поддержаны.
  Отзыв принимает form/JSON и Basic/body client auth, проверяет клиента в
  транзакции и отзывает access JWT либо старый opaque refresh по индексу YDB.
  Отзыв старого refresh после ротации закрывает всю family. Неизвестный токен
  не раскрывает своё существование. Соль refresh должна
  совпадать с Python-версией. Межверсионная ротация на общей локальной YDB
  прошла; Gateway и внешний RP ещё не проверены. Детали — [обмен](../../docs/rust-migration/verification-2026-10-04-oidc-code.md),
  [refresh](../../docs/rust-migration/verification-2026-10-04-oidc-refresh.md),
  [отзыв](../../docs/rust-migration/verification-2026-10-04-oidc-revoke.md),
  [discovery](../../docs/rust-migration/verification-2026-10-04-oidc-discovery.md),
  [JWKS](../../docs/rust-migration/verification-2026-10-04-oidc-jwks.md) и
  [UserInfo](../../docs/rust-migration/verification-2026-10-04-oidc-userinfo.md).
  Отдельный `ID_OIDC_AUTHORIZE_PILOT_ENABLED=true` открывает локальные
  `/oauth/authorize`, `/prepare`, `/approve` и `/deny`: повторный SSO выдаёт
  code напрямую, первый consent проходит через Topcoat
  `ID_WEB_CONSENT_PILOT_ENABLED=true`, затем Rust атомарно создаёт code и
  сохраняет grant. Локальный Chromium E2E с одноразовой YDB запускается
  `scripts/smoke-web-consent-live.sh` после сборки бинарников и `migrate_ydb`;
  он проверяет реальный SSR, CSRF, PKCE, replay и отказ. Оба флага ограничены
  пилотом; подробности —
  [в проверке](../../docs/rust-migration/verification-2026-10-04-oidc-authorize.md).
  `ID_AUTH_SECURITY_READ_PILOT_ENABLED=true` открывает чтение
  `/mfa/status`, `/passkeys`, `/email` и единый `/security` в авторизованном
  снимке YDB. При `ID_WEB_SECURITY_PILOT_ENABLED=true` Topcoat показывает
  SSR-раздел `/account?section=security`. Проверены активная сессия с MFA,
  приоритет токена, счётчик recovery codes и безопасный вывод имён passkeys.
  Та же локальная проверка покрывает `/api/v1/auth/login-history`: до 100
  событий владельца, без выдачи при непроверенном MFA.
  Production Gateway также направляет точный GET/OPTIONS `/api/v1/auth/email`
  в Rust; ответ сравнен с Python на выделенном аккаунте до переключения и
  проверен через Gateway после него. Флаг
  `ID_WEB_LOGIN_HISTORY_PILOT_ENABLED=true` показывает SSR-раздел
  `/account?section=activity`; `scripts/smoke-web-history.sh` проверяет
  экранирование данных события и переход гостя на вход.
  `ID_AUTH_EMAIL_CANCEL_PILOT_ENABLED=true` открывает DELETE/OPTIONS
  `/api/v1/auth/email/change`. Операция транзакционно удаляет ожидающие
  неподтверждённые адреса и их confirmations, сохраняет основной и
  подтверждённые адреса. Локальная проверка включает десять конкурентных
  отмен; production Gateway и YDB проверены на выделенном тестовом аккаунте.
  POST `/passkeys/rename` и `/passkeys/delete` можно включить отдельно через
  `ID_AUTH_PASSKEY_MANAGEMENT_ENABLED=true`; Topcoat показывает действия при
  `ID_WEB_PASSKEY_MANAGEMENT_ENABLED=true`. Операции требуют MFA proof,
  недавнего входа и CSRF для cookie. Переименование сохраняет WebAuthn
  credential; удаление в той же транзакции убирает запись Rust login-index, а
  удаление последнего основного фактора — бесполезные recovery codes. Локальный
  TOTP-пилот также включает эти маршруты для своих интеграционных сценариев.
  Gateway направляет переименование и удаление в Rust при
  `gateway_rust_passkey_rename=true` и `gateway_rust_passkey_delete=true`.
  Удаление транзакционно записывает уведомление в `id_security_mail`;
  выборочный Rust jobs timer доставляет только уведомления об удалении ключа.
  Отдельный `ID_WEB_PASSKEY_REGISTRATION_ENABLED=true` показывает добавление
  ключа в Topcoat даже когда ключей ещё нет. После первой регистрации страница
  показывает резервные коды один раз без перезагрузки. Для production API
  требуется отдельный `ID_AUTH_PASSKEY_REGISTRATION_ENABLED=true`, общий
  `ID_MFA_SEAL_KEY_B64`, готовый passkey-index и точные Gateway-маршруты
  `/passkeys/begin` и `/passkeys/complete`; одного флага UI недостаточно.
  Детали прежней проверки чтения —
  [в отчёте](../../docs/rust-migration/verification-2026-10-04-security-read.md).
  В production TOTP и регенерация резервных кодов доступны через отдельные
  `ID_AUTH_TOTP_ENABLED=true` и `ID_WEB_TOTP_ENABLED=true` с точным Gateway
  переключателем `gateway_rust_totp_management=true`. Нужны общий MFA seal key,
  HTTPS trusted origin, secure cookies и ранний Rust rollout. Текущее
  состояние и ограничение по authenticated E2E записаны в
  [production-отчёте](../../docs/rust-migration/production-totp-management-2026-10-06.md).
  Для нового TOTP локальный пилот включается отдельно:
  `ID_AUTH_TOTP_PILOT_ENABLED=true` включает `/mfa/totp/begin`,
  `/mfa/totp/confirm`, `/mfa/totp/disable` и `/mfa/recovery/regenerate`,
  а `ID_WEB_TOTP_PILOT_ENABLED=true` показывает управление
  на странице безопасности. Требуются `DJANGO_DEBUG=true`, локальный YDB и
  `ID_MFA_SEAL_KEY_B64` (32 случайных байта, base64). Ключ должен быть общим
  для Rust и переходного Django; его отсутствие при чтении зашифрованного
  credential приводит к отказу, а не обходу MFA. Секрет ожидает подтверждения
  не более 10 минут в подписанной сессии, затем TOTP и seed резервных кодов
  записываются в YDB в одной транзакции. Перед настройкой нужны недавний вход
  и подтверждённая почта. Локальный тест выполняется после `migrate_ydb`:

  ```sh
  ID_AUTH_TOTP_PILOT_ENABLED=true ID_MFA_SEAL_KEY_B64=<base64-32-bytes> \
    cargo test --locked -p id-runtime --test totp_setup_http_ydb -- --ignored
  ```

  Тест требует `YDB_ENDPOINT=grpc://localhost:2136` и `YDB_DATABASE=/local`;
  проверяет неверный код, replay, 100 конкурентных подтверждений и 100
  конкурентных отключений и 100 запросов ротации с одним `Idempotency-Key`.
  Отключение удаляет резервные коды, если TOTP был последним основным фактором.
  `passkey_management_http_ydb` отдельно проверяет принадлежность, CSRF,
  свежесть входа, сохранение credential при rename и 100 конкурентных удалений
  последнего ключа с одним успешным ответом.
  Для сохранения действующих ключей добавлен импорт исторического allauth
  registration response через `webauthn-rs` и read-only аудит:

  ```sh
  ID_WEBAUTHN_RP_ID=<existing-rp-id> ID_WEBAUTHN_ORIGIN=<existing-origin> \
    idctl passkey-audit --require-convertible
  ```

  Аудит выводит только счётчики совместимых, повреждённых и повторяющихся
  credential IDs. Он не исправляет данные. RP ID и origin должны совпадать с
  действующей WebAuthn-конфигурацией; production-результат ещё не получен.
  Локальная регистрация ключей доступна дополнительно при
  `ID_AUTH_PASSKEY_REGISTRATION_PILOT_ENABLED=true` (вместе с TOTP pilot),
  `ID_WEBAUTHN_RP_ID` и `ID_WEBAUTHN_ORIGIN`. Rust выдаёт challenge и
  сохраняет WebAuthn-состояние в серверной сессии YDB на пять минут.
  Завершение атомарно удаляет challenge, записывает credential, создаёт
  recovery codes при первом факторе и обновляет MFA marker сессии. До запуска
  маршрута `idctl passkey-index` создаёт таблицу индекса, повторяемо переносит
  существующие credential IDs и сверяет владельцев в обе стороны. Если
  найден дубликат или повреждённая запись, отметка готовности снимается и
  Rust-регистрация закрыта. Для локальных тестов:

  ```sh
  cargo test --locked -p id-runtime --test passkey_index_ydb -- --ignored
  ID_AUTH_PASSKEY_REGISTRATION_PILOT_ENABLED=true \
    ID_WEBAUTHN_RP_ID=id.example.invalid \
    ID_WEBAUTHN_ORIGIN=https://id.example.invalid \
    cargo test --locked -p id-runtime --test passkey_registration_ydb -- --ignored
  ```

  Тест требует мигрированный локальный YDB, `DJANGO_DEBUG=true`,
  `ID_AUTH_TOTP_PILOT_ENABLED=true`, `ID_MFA_SEAL_KEY_B64` и синтетический
  `DJANGO_SECRET_KEY`; использует два экземпляра и 20 параллельных завершений.
  `scripts/smoke-web-passkey-native-live.sh` отдельно открывает настоящий
  Topcoat-кабинет в Chromium с временным виртуальным WebAuthn-устройством,
  регистрирует ключ через Rust API и проверяет запись в локальной YDB. Этот
  прогон входит в основной CI и не заменяет проверку на физическом iPhone/Safari.
  В production Gateway направляет `/api/v1/auth/passkeys/begin` и `/complete`
  в основной Rust API-контейнер; его ревизию нужно обновить при исправлении
  регистрации. Контейнер API-мутаций обслуживает другие маршруты.
  `ID_AUTH_PASSKEY_LOGIN_PILOT_ENABLED=true` вместе с локальным
  `ID_AUTH_LOGIN_PILOT_ENABLED=true` открывает `/passkeys/login/begin` и
  `/complete`. Challenge хранится пять минут в YDB и потребляется ровно один
  раз. Rust проверяет подпись WebAuthn, затем в транзакции повторно проверяет
  владельца, состояние ключа и аккаунта перед выдачей сессии и JWT. Проверка
  с синтетическим ключом и двумя экземплярами:

  ```sh
  cargo test --locked -p id-runtime --test passkey_login_ydb -- --ignored
  ```

  Ограничение о старом Python writer относилось к смешанному canary и больше
  не применимо к текущей Rust-only маршрутизации. До заявления о полном
  принятии нужны browser E2E, реальный authenticator и аудит действующих
  credentials.
  Ранее выпущенные ключи по-прежнему читаются Rust-аудитом.
  Ротация требует свежей MFA-сессии, сохраняет один новый набор при повторе
  запроса и не раскрывает код после его использования.
  `scripts/smoke-web-totp-live.sh` отдельно проводит Chromium через Topcoat,
  same-origin proxy, Rust API и локальную YDB. Это ещё не допуск в production:
  нужны тест через настоящий Gateway, Firefox/WebKit,
  rollback-проверка на общем YDB и проверка хранения
  ключа в Lockbox. Результаты записаны
  [в проверке](../../docs/rust-migration/verification-2026-10-04-totp-enrollment.md).
- `id-jobs`: отдельный Rust worker для уведомлений о новом устройстве.
  Забирает ограниченную партию из YDB по lease, отправляет через SMTP и
  фиксирует результат. Повторяется только подтверждённый `ABORTED`; неизвестный
  результат commit автоматически не переигрывается. При потере SMTP ACK
  возможно повторное письмо. `Dockerfile.jobs` собирает отдельный образ без
  Python. В режиме `--serve` он принимает приватные POST-вызовы
  `/internal/jobs/mail` (версионированные event ID из YMQ) и
  `/internal/jobs/publish` (timer повторно публикует готовые outbox IDs) и
  `/internal/jobs/recover` (резервная прямая SMTP-обработка). HTTP-режим требует
  `ID_JOBS_HTTP_ENABLED=true`; права вызова должны ограничиваться IAM
  самого контейнера, а маршруты не добавляются в публичный Gateway.
  Тело одного YMQ-сообщения: `{"version":1,"kind":"new_device_mail","event_id":42}`;
  endpoint получает его внутри стандартного Yandex `messages[].details.message.body`.
  HTTP batch ограничен десятью сообщениями/записями на вызов, чтобы даже
  последовательные SMTP timeout не превысили лимит контейнера.
  [Формат YMQ-триггера](https://yandex.cloud/en/docs/serverless-containers/concepts/trigger/ymq-trigger)
  и [формат timer-триггера](https://yandex.cloud/en/docs/serverless-containers/concepts/trigger/timer)
  проверены локальными запросами к настоящему YDB/SMTP.

Отдельный `POST /refresh-gravatars` включается через
`ID_GRAVATAR_JOB_ENABLED=true` и `GRAVATAR_BATCH_LIMIT` (1–100). Он выбирает
только согласившиеся профили, проверяет адрес и состояние перед атомарной
публикацией, ограничивает размер/формат изображения и записывает JPEG в
Object Storage. Маршрут не запускает восстановление почты или удалений.
Production-таймер теперь вызывает его на Rust jobs; см.
[отчёт о переключении](../../docs/rust-migration/production-rust-stack-2026-10-05.md).

Для локального запуска `id-jobs` нужны общие `YDB_*` и `EMAIL_HOST`,
`EMAIL_PORT`, `DEFAULT_FROM_EMAIL`, при необходимости `EMAIL_HOST_USER` и
`EMAIL_HOST_PASSWORD`. `EMAIL_USE_TLS=false` разрешён только для loopback SMTP.
После подготовки схемы запускайте `cargo run --locked --bin id-jobs -- --limit 25`.
Если задан `YMQ_QUEUE_URL`, дополнительно нужны `YMQ_ACCESS_KEY_ID` и
`YMQ_SECRET_ACCESS_KEY`; запросы подписываются SigV4. Rust-вход отправляет
уведомление в YMQ после commit без ожидания ответа очереди, а минутный timer
повторно публикует готовые записи. Пятиминутный timer доставляет их напрямую
через SMTP, если очередь или процесс публикации недоступны.
[YMQ требует SQS-совместимую подпись и статический ключ](https://yandex.cloud/en/docs/message-queue/api-ref/).
Временная Python-версия продолжает отправлять свои уведомления прежним путём;
Rust-job обрабатывает только durable intents от Rust-входа.

Terraform отдельно включает постоянную очередь `enable_rust_mail_queue=true`,
затем приватный worker и три trigger при `enable_rust_mail_job=true`.
Для worker нужны CI-тег с точным digest образа и SMTP host/from. Оба флага по
умолчанию выключены. При откате worker можно отключить, сохранив очередь;
её удаление защищено `prevent_destroy`. Terraform не применялся к облаку.
Подпись и отправка проверены на loopback SQS fixture, но совместимость с
настоящим YMQ, IAM и масштабирование требуют staging-репетиции.

## Локальные проверки

`ID_AUTH_PASSWORD_CHANGE_PILOT_ENABLED=true` включает
`POST /api/v1/auth/change_password` в local debug YDB, а в production только
при отдельном `ID_RUST_EARLY_ROLLOUT_ENABLED=true`. Он проверяет текущий пароль вне async
executor, создаёт новый Django-читаемый Argon2id хеш с прежней стоимостью и
одной YDB-транзакцией закрывает сессии, account refresh, OIDC tokens и
ожидающие authorization codes. Неверный CSRF и сессия без требуемого MFA proof
не меняют пароль. Интеграционный тест на локальной YDB проверяет также две
одновременные попытки: успех получает только одна. Текущая политика нового
пароля покрывает длину, полностью числовые значения, повтор старого пароля,
словарь распространённых паролей и слова из username/email/имени. Словарь
включён в Rust image из Django 5.2.15 вместе с его лицензией; Python в runtime
для этой проверки не нужен. Смена пароля, отзыв credentials и запись в
`id_password_mail` происходят в одной YDB-транзакции. Команда
`idctl password-mail-schema` создаёт и повторно проверяет отдельный Rust
outbox; её запускают после базовой YDB-миграции. Приватный `id-jobs`
обрабатывает уведомление через YMQ либо адресный таймер
`/internal/jobs/recover-mail`, который не запускает удаление аккаунтов и
экспорты. Terraform включает этот таймер на существующем jobs-контейнере
отдельным `enable_rust_mail_recovery_timer`. После окончательного исхода worker очищает адрес получателя
и связь с user ID в outbox. При неоднозначном ответе SMTP возможно второе письмо, но не повторная
смена пароля. Настоящий YMQ, производственная почта и Gateway требуют отдельной
проверки перед переключением публичного маршрута.
Удаление passkey в Rust атомарно записывает `id_security_mail` с типом
`passkey_removed`. `idctl security-mail-schema` создаёт и проверяет таблицу
до обновления API/jobs. Приватный mail worker обрабатывает запись через
версионированное YMQ-сообщение `security_mail` либо отдельный
`/internal/jobs/recover-security-mail` timer. Он не выбирает письма о смене
пароля и подтверждении email; Terraform включает его флагом
`enable_rust_security_mail_recovery_timer`;
после окончательного исхода он очищает адрес и связь с пользователем.
Локальный YDB-тест проверяет две успешные операции удаления, 100 конкурентных
попыток повторно удалить последний ключ и ровно два mail intents; отдельный
loopback SMTP-тест проверяет доставку один раз и очистку PII. Публичный
`/api/v1/auth/passkeys/delete` теперь направлен в Rust; новая схема, API/jobs
images и селективный timer активны в production. Аутентифицированное удаление
и доставка в настоящий почтовый ящик ещё не подтверждены.
При `ID_WEB_SECURITY_PILOT_ENABLED=true` и
`ID_WEB_PASSWORD_CHANGE_PILOT_ENABLED=true` Topcoat показывает форму на
`/account?section=security`. `scripts/smoke-web-security.sh` проверяет SSR и
выдачу отдельного JS-файла; реальный YDB-тест маршрута запускается в CI.
Изолированный jobs-маршрут для уведомлений о смене пароля уже развернут в
production; его таймер и публичный Rust API пока выключены. Ревизия и проверки
описаны в [отчёте](../../docs/rust-migration/production-password-change-jobs-2026-10-06.md).

`ID_WEB_RECOVERY_PILOT_ENABLED=true` включает Topcoat-страницы
`/forgot-password` и `/reset-password` и ссылку из формы входа. Ссылка сброса
передаёт ключ только во фрагменте `#key=…`; браузер удаляет фрагмент из адреса
перед запросом API. Формы используют переходные
`/api/v1/auth/password/reset/request` и `/confirm`. Rust API реализует оба
маршрута при `ID_AUTH_PASSWORD_RESET_PILOT_ENABLED=true` вместе с
`ID_AUTH_FORM_TOKEN_ENABLED=true`. Нужен отдельный 32-байтовый hex-ключ
`ID_PASSWORD_RESET_HMAC_KEY` из Lockbox. `idctl password-reset-schema` создаёт
и проверяет intent и зависимый `id_password_mail` для уведомления после смены
пароля. `id-jobs` при
`ID_PASSWORD_RESET_MAIL_ENABLED=true` использует тот же ключ и
`ID_PASSWORD_RESET_URL` (`https://…/reset-password`) для отправки ссылки.
Запрос возвращает одинаковый результат для известного и неизвестного адреса;
ключ HMAC не хранится в YDB. Подтверждение атомарно меняет пароль, закрывает
старые sessions/tokens и добавляет уведомление в outbox. После успеха intent
очищает email и password version; истёкшие intents удаляет timer job.
Локальная проверка HTTP→YDB→SMTP и конкурентного потребления описана в
[отчёте](../../docs/rust-migration/verification-2026-10-05-password-reset.md).
Terraform включает API, UI и jobs вместе через `enable_rust_password_reset`,
по умолчанию `false`; это требует приватного mail worker, YMQ и
`ID_PASSWORD_RESET_HMAC_KEY` в runtime Lockbox. Django-ссылки, уже отправленные
до переключения, Rust-маршрут не распознаёт; их срок жизни нужно учесть при
маршрутизации или предложить пользователю запросить новую ссылку.
`scripts/smoke-web-recovery.sh` проверяет SSR, заголовки и JS без YDB.
`scripts/smoke-web-recovery-live.sh` с локальной YDB и Chromium проверяет
форму Topcoat, CSRF в свежем браузере, одноразовость ссылки и отзыв сессии.
Проверка через настоящий Gateway и production SMTP ещё не пройдена.

`ID_AUTH_EMAIL_VERIFY_PILOT_ENABLED=true` добавляет Rust
`/api/v1/auth/email/verification/request` и `/confirm`. Перед запуском
`idctl email-verify-schema` создаёт одноразовый YDB intent; API и mail job
используют отдельный `ID_EMAIL_VERIFY_HMAC_KEY`. При
`ID_EMAIL_VERIFY_MAIL_ENABLED=true` приватный `id-jobs` отправляет ссылку на
`ID_EMAIL_VERIFY_URL` через существующие YMQ/SMTP и timer recovery.
`ID_WEB_EMAIL_VERIFY_PILOT_ENABLED=true` включает Topcoat `/verify-email`:
ключ читается из URL fragment и удаляется из адреса до POST; есть повторный
запрос письма. Локальный HTTP→YDB→SMTP тест проверяет одноразовость и
конкурентность. [Отчёт](../../docs/rust-migration/verification-2026-10-05-email-verify.md).
Terraform-флаг `enable_rust_email_verify` выключен по умолчанию; для него нужны
Rust API/UI, приватный mail worker, очередь и ключ в Lockbox.

`idctl magic-link-schema` создаёт повторяемую таблицу mail intents. Rust API
обрабатывает `/api/v1/auth/magic-link/request` и оба метода `/consume` при
`ID_AUTH_MAGIC_LINK_REQUEST_PILOT_ENABLED=true` и
`ID_AUTH_MAGIC_LINK_CONSUME_ROLLOUT_ENABLED=true`. Запрос проверяет tenant,
membership и HTTPS callback по `ID_MAGIC_LINK_REDIRECT_ORIGINS`, ограничивает
частоту через общий YDB cache и возвращает одинаковый результат для известного
и неизвестного email. Транзакция записывает хеш одноразового токена и mail
intent; `id-jobs` при `ID_MAGIC_LINK_MAIL_ENABLED=true` публикует intent в
YMQ и доставляет письмо приватным worker, а таймер восстанавливает доставку
после сбоя. Jobs использует тот же `ID_TOKEN_HASH_SECRET` (либо переходный
`DJANGO_SECRET_KEY`) и `ID_MAGIC_LINK_PUBLIC_URL`. Ссылка содержит подписанный
tenant/callback; браузерный GET выдаёт одноразовый код для BFF, POST — session
token. Истёкшие intents и токены удаляются jobs. Локальный тест с настоящей
YDB и SMTP-фикстурой проверяет request → письмо → redirect → replay, второй
тест — гонку 100 погашений. Terraform-флаг `gateway_rust_magic_link` выключен
по умолчанию и требует Rust API, jobs, exchange и явный allowlist. Уже
отправленные Django-ссылки нового tenant-подписания не имеют; переключение
маршрута должно учитывать их 15-минутный срок. Production SMTP и Gateway для
этого сценария ещё не проверены.

`ID_AUTH_SIGNUP_PILOT_ENABLED=true` включает Rust `/api/v1/auth/signup` после
активации form-token и email-verification. Аккаунт, master identity, email lookup,
согласия (включая guardian consent), дата рождения и intent письма создаются
одной транзакцией YDB; до подтверждения
сессия не выдаётся. `ID_WEB_SIGNUP_PILOT_ENABLED=true` включает Topcoat SSR
`/signup`. Локальный `scripts/smoke-web-signup-live.sh` проверяет Chromium,
Topcoat, Axum и YDB для взрослых и несовершеннолетних. Страница Topcoat уже
работает в production через отдельный флаг `gateway_rust_signup_page`; API
регистрации там пока остаётся прежним. Terraform-флаг `enable_rust_signup` по умолчанию выключен
и требует включённого mail job через `enable_rust_email_verify`.
[Отчёт](../../docs/rust-migration/verification-2026-10-05-signup.md).

Rust 1.98.1 закреплён в `rust-toolchain.toml`, зависимости — в `Cargo.lock`.
Из этой директории:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --workspace --bins
```

После запуска локального YDB: `bash scripts/smoke-pilot.sh` проверяет реальные
HTTP-серверы на временных портах и останавливает только запущенные им процессы.
`bash scripts/smoke-web-login.sh` отдельно проверяет opt-in SSR login, assets,
CSP и безопасное поведение формы без JavaScript; ему YDB не нужен.

Для реального YDB используйте отдельный локальный контейнер:

```sh
docker run -d --rm --name id-rust-ydb --hostname localhost \
  -p 127.0.0.1:2136:2136 -p 127.0.0.1:8765:8765 \
  ydbplatform/local-ydb@sha256:9e46fd45875551a75bcf34d0bb9ca0baa1d8763a4ccf2070af45f4467c4b7402
export YDB_ENDPOINT=grpc://localhost:2136
export YDB_DATABASE=/local
export YDB_CREDENTIALS_MODE=anonymous
cargo run --locked --bin idctl -- ydb-probe
cargo run --locked --bin idctl -- legacy-schema --apply
cargo run --locked --bin idctl -- legacy-schema
cargo run --locked --bin idctl -- cache-schema
cargo test --locked -p id-runtime --test ydb_pilot -- --ignored --nocapture
cargo test --locked -p id-runtime --test cache_store_ydb -- --ignored --nocapture
cargo test --locked -p id-runtime --test form_token_http_ydb -- --ignored --nocapture
cargo test --locked -p id-runtime --lib counts_collisions_across_pages_without_exposing_addresses -- --ignored --nocapture
```

После `idctl legacy-schema --apply` можно проверить email-инвентаризацию:

```sh
cargo run --locked --bin idctl -- login-email-audit --require-unambiguous
cargo run --locked --bin idctl -- cleanup-tokens
```

Команда выводит только агрегаты. Она также проверяет отсутствие пропущенных,
устаревших и осиротевших строк синхронного email lookup. Нулевой отчёт —
необходимая предварительная проверка, но не замена аудита всех writers.

Затем можно проверить чтение синтетической Django-сессии из той же локальной базы:

```sh
cargo test --locked -p id-runtime --test session_store_ydb -- --ignored --nocapture
cargo test --locked -p id-runtime --test profile_store_ydb -- --ignored --nocapture
cargo test --locked -p id-runtime --test login_preflight_ydb -- --ignored --nocapture
ID_AUTH_SESSIONS_PILOT_ENABLED=true DJANGO_DEBUG=true DJANGO_SECRET_KEY=synthetic-local-secret-min-32-characters cargo test --locked -p id-runtime --test session_issuer_ydb -- --ignored --nocapture
ID_AUTH_ME_ENABLED=true DJANGO_SECRET_KEY=synthetic-local-secret-min-32-characters MEDIA_PUBLIC_BASE_URL=https://storage.yandexcloud.net/synthetic-id-media cargo test --locked -p id-runtime --test me_http_ydb -- --ignored --nocapture
```

`idctl mfa-session-audit --require-proven-mfa` проходит все записи
`django_session`, проверяет подписанную сессию и действующие связи в YDB,
затем выводит только агрегированные счётчики. Ненулевой
`eligible_mfa_unproven` завершает команду с ошибкой. `ineligible` включает
гостевые и другие сессии, которые Rust не авторизует; ноль MFA-пробелов сам
по себе не означает готовность к canary. Для проверки нужны действующие
`DJANGO_SECRET_KEY` и fallback keys, без вывода их или session tokens в отчёт.
Страницы читаются разными снапшотами, поэтому аудит повторяют после остановки
старых writers и непосредственно перед переключением.

Этот тест использует отрицательный synthetic account ID, проверяет отзыв,
expiry, смену password hash, отсутствие binding, suspension master identity и
pending deletion, затем удаляет созданные строки. Он отказывается
работать с endpoint вне `localhost:2136` и database вне `/local`.

Тест создаёт уникальную временную таблицу и удаляет её, проверяет nullable и
микросекундный Timestamp, затем 100 раз запускает 100 одновременных попыток
потребления одной записи через два независимых SDK-клиента. В каждом раунде
требуется ровно один победитель; `null`, отсутствие записи и повтор отклоняются.
Отдельно проверяются 100 конкурентных `add` и 100 `incr`: одна вставка,
значения счётчика 1..100 без потерь и неизменный TTL. Горячие инкременты
очередятся внутри одного экземпляра; между экземплярами действует YDB.
`ID_YDB_RACE_ROUNDS=1` сокращает локальную диагностику; полный CI использует 100.
Это проверка транзакционного механизма SDK, **не** тест всех credentials и
двух экземпляров будущего приложения. Fault injection и неоднозначный commit
предстоит проверить отдельно. Глобального `idempotent(true)` нет.

```sh
cargo run --locked --bin id-api
# В другом терминале (для контейнера HOST=0.0.0.0):
HOST=127.0.0.1 PORT=3000 cargo run --locked --bin id-web
```

API по умолчанию слушает 8081. Для защищённого YDB: `grpcs://host:port`, отдельный
`YDB_DATABASE`, `YDB_CREDENTIALS_MODE=metadata` либо `token` + `YDB_TOKEN`.
Пользовательские CA задаются через `YDB_CA_FILE`; проверка TLS не отключается.
Anonymous разрешён только на loopback. Секреты не передаются аргументами CLI.
Metadata-режим ещё не прошёл IAM renewal/freeze-resume qualification.

После `idctl cache-schema` можно запустить
`cargo run --locked --bin idctl -- cache-audit --require-portable`.
Команда читает строки общей таблицы кэша постранично и выводит
только счётчики: `portable`, `legacy`, `expired`, `malformed`. Флаг
`--require-portable` завершает команду с ошибкой при действующих legacy или
повреждённых записях. Аудит запускается после остановки старых writers и
повторяется перед canary; он не доказывает совместимость всех auth flows.

## Проверка старых данных

Эталоны в `crates/id-compat/tests/fixtures/django.json` полностью синтетические,
сгенерированы установленными Django/allauth, содержат Unicode, длинный пароль,
сжатую и несжатую сессию, старое authentication time и потраченные recovery codes.
Обратную проверку выполняет:

```sh
cargo run --locked --bin idctl -- compat-fixtures \
  crates/id-compat/tests/fixtures/django.json /tmp/rust-compat.json
```

Историческая Python-проверка обратного чтения удалена вместе с Django-кодом.
`id-compat` и интеграционные Rust-тесты проверяют синтетические эталоны;
действующие credentials и identity требуют отдельной сверки перед изменением
production-маршрутов.

## Ограничения адаптеров

Успешная подпись/пароль **не выдаёт доступ**. До подключения HTTP нужны проверки
владельца и активности master identity, MFA, CSRF
Origin/Referer, атомарности и всех действующих форматов на настоящих данных.
Текущий read-only session store уже проверяет Django backend, account activity,
DB expiry, password-bound hash, session metadata, master identity status и
pending deletion на локальном YDB.
CSRF-модуль сравнивает только токены. Recovery-модуль вычисляет индекс и не
сохраняет `used_mask`; сохранение должно быть атомарным. Он покрывает стандартный
seed-формат allauth (10 × 8 цифр), а migrated_codes, другой count/digits и
пользовательские encrypt/decrypt adapters требуют отдельных адаптеров.

Ограничения работы verifier: Argon2 ≤256 MiB, time cost ≤10, parallelism ≤16;
BCrypt cost ≤16; PBKDF2 ≤10 млн итераций; пароль ≤1 MiB; session JSON ≤1 MiB.
Выход за предел возвращает отдельную ошибку и не вызывает сброс credentials.
До rollout инвентаризация production должна доказать, что все валидные записи
поддерживаются, либо лимиты/адаптеры корректируются. Нагрузка хеширования не
снижается; будущий HTTP обязан использовать ограниченный blocking pool.

Повторяющиеся Authorization/X-Session-Token отвергаются как неоднозначные.
Точное поведение Gateway с такими заголовками ещё нужно проверить. Срок сессии
определяется записью БД; signed timestamp не заменяет срок или MFA freshness.
