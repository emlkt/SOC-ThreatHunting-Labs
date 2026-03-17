# Расследование инцидента: C2-коммуникация и пост-эксплуатация (Splunk)

**Дата прохождения:** 17.03.2026  
**Ссылка на челлендж:** [Threat Hunting with Splunk](https://app.letsdefend.io/challenge/threat-hunting-with-splunk)

---

## Описание:

В корпоративной сети сработало оповещение о подозрительном файле с аномальным расширением. Система безопасности зафиксировала потенциальную компрометацию рабочей станции.

## Использованные инструменты и источники

1. **Splunk** для анализа загруженных логов (source="sysmon.json")
2. **MITRE ATT&CK Framework**

---

### 1. Поиск файла, обеспечившего удалённый доступ (вопросы 1-3)

1. Загрузила логи в Splunk
2. Начала с поиска файлов с подозрительными расширениями

#### Было найдено событие:
```
EventID: 11 (FileCreate)
TargetFilename: C:\Users\LetsDefend\Downloads\application_form.pdf.exe
Image: C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
Hashes: SHA256=B5BA9F646A7A6A3AECB51B38891B16D1E8B05F063D7B2359C33CF80E36342D18
```

(файл имеет двойное расширение. Выглядит как документ, но является исполняемым. Скачан через браузер Edge)

#### Для поиска источника загрузки:
1. Искала события с Zone.Identifier (метка Windows для файлов из интернета) + TargetFilename="*application_form.pdf.exe:Zone.Identifier"

#### Найдено событие:
```
EventID: 15 (FileCreateStreamHash)
ReferrerUrl=`http://13[.]232[.]55[.]12:8080/`
TargetFilename: ...application_form.pdf.exe:Zone.Identifier
```

(ReferrerUrl содержит точный адрес, откуда был скачан файл. ZoneId=3 подтверждает, что из интернета)

#### Ответы:
1. Полный путь к файлу - `C:\Users\LetsDefend\Downloads\application_form.pdf.exe`
2. Время создания файла на диске - `2024-06-06 09:24:18 UTC`
3. URL загрузки - `http://13[.]232[.]55[.]12:8080/application_form.pdf.exe`

---

### 2. Поиск C2-коммуникации (вопрос 4)

1. После нахождения файла искала его запуск - событие создания процесса
2. Фильтр: `EventCode=3 AND Image="*application_form.pdf.exe"`
3. Нашла запуск, затем сразу проверила сетевую активность от этого процесса

#### Найдено сетевое событие:
```
EventID: 3
Image: C:\Users\LetsDefend\Downloads\application_form.pdf.exe
DestinationIp: 13.232.55.12
DestinationPort: 30
Protocol: tcp
Initiated: true
RuleName: technique_id=T1036,technique_name=Masquerading
```

(Тот же IP, откуда скачали файл. Порт 30 достаточно нестандартный. Initiated=true означает, что наш хост сам инициировал соединение, а это похоже на реверсшелл)

#### Ответ:
4. IP и порт - `13.232.55.12:30`

---

### 3. Действия злоумышленника после получения доступа (вопросы 5-8)

#### 3.1 Запуск cmd.exe (вопрос 5)

1. Искала события, где вредоносный процесс создал дочерний процесс
2. Фильтр: `EventCode=1 AND ParentImage="*application_form.pdf.exe"`

#### Найдено:
```
EventID: 1
Image: C:\Windows\system32\cmd.exe
ParentImage: C:\Users\LetsDefend\Downloads\application_form.pdf.exe
UtcTime: 2024-06-06 09:28:55
```

(Вредонос запустил командную строку для выполнения системных команд)

#### Ответ:
5. Время запуска cmd `2024-06-06 09:28:55 UTC`

---

#### 3.2 Вторая команда в сессии (вопрос 6)

1. Искала команды, выполненные через cmd.exe после его запуска
2. Фильтр: `"Event.System.EventID"=1 AND ParentImage="*cmd.exe" | sort _time`

#### Найдено:
```
EventID: 1
CommandLine: tasklist
Image: C:\Windows\System32\tasklist.exe
ParentImage: C:\Windows\System32\cmd.exe
RuleName: technique_id=T1057,technique_name=Process Discovery
```

(Первой командойбыл `whoami`. Второй `tasklist` для разведки запущенных процессов)

#### Ответ:
6. Вторая команда - `tasklist`

---

#### 3.3 Создание нового пользователя (вопрос 7)

1. Искала команды создания учётных записей
2. Фильтр: `CommandLine="*net*user*" AND CommandLine="*/add*"`

#### Найдено:
```
"Event.System.EventID"=1
"CommandLine": "C:\\Windows\\system32\\net1 user jumpadmin U7gk54skuvhs@1 /add"
"OriginalFileName": "net1.exe"
```

(Злоумышленник создал учётную запись для постоянного доступа. Пароль передан в открытом виде и виден в логе)

#### Ответ:
7. Учётная запись - `jumpadmin:U7gk54skuvhs@1`

---

#### 3.4 Путь к скрипту для пост-эксплуатации (вопрос 8)

1. Искала создание скриптов, запущенных через PowerShell
2. Фильтр: `EventCode=11 AND *powershell.exe* AND (FileName="*.ps1" OR FileName="*.bat")`

#### Найдено:
```
EventID: 11 (FileCreate)
TargetFilename: C:\Windows\Temp\tmp.ps1
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
RuleName: technique_id=T1059.001,technique_name=PowerShell
```

(Скрипт загружен в tmp (типичное место для вредоносных файлов). Запуск через PowerShell может указывать на пост-эксплуатацию)

#### Ответ:
8. Путь к скрипту - `C:\Windows\Temp\tmp.ps1`

---

### 4. Обход политики, имя правила и контекст (вопросы 9-11)

#### 4.1 Время обхода политики выполнения PowerShell (вопрос 9)

1. Фильтр: `EventCode=1 AND Image="*powershell.exe" + *bypass*`

#### Найдено:
```
"EventID": 1,
"CommandLine": "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -ep bypass",
"CurrentDirectory": "C:\\Windows\\Temp\\",
"UtcTime": "2024-06-06 09:42:08.639",
"RuleName": "technique_id=T1059.001,technique_name=PowerShell"
```

( -ep bypass отключает проверку политик выполнения для данной сессии PowerShell)

#### Ответ:
9. Время обхода политики - `2024-06-06 09:42:08 UTC`

---

#### 4.2 Правило фаервола (вопросы 10-11)

1. Искала изменения в правилах брандмауэра
2. Фильтр: `EventCode=13 AND *Firewall*`

#### Найдено:
```
EventID: 13 (RegistryValueSet)
TargetObject: HKLM\...\FirewallRules\{...}
Details: Action=Block|Active=TRUE|Dir=Out|RA4=13.232.55.12|Name=secevent1
User: NT AUTHORITY\LOCAL SERVICE
```

(cоздано правило блокировки исходящего соединения на IP злоумышленника)

#### Ответы:
10. Имя правила - `secevent1`
11. Контекст применения - `NT AUTHORITY\LOCAL SERVICE`

---

Добавлю еще про пользу ProcessGuid - по нему мы можем отслеживать родительско-детские связи. И еще GrantedAccess: 0x1fffff - был запрошен полный доступ к памяти процесса (больше, чем нужно для легитимных задач)
```
"CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9e664|C:\\Windows\\System32\\KERNELBASE.dll+8e73|C:\\Windows\\System32\\KERNELBASE.dll+63c3|C:\\Windows\\System32\\ADVAPI32.dll+17c50|UNKNOWN(000000000262C5D8)", 
"GrantedAccess": "0x1fffff", 
"RuleName": "technique_id=T1055.001,technique_name=Dynamic-link Library Injection", 
"SourceImage": "C:\\Users\\LetsDefend\\Downloads\\application_form.pdf.exe", 
"SourceProcessGUID": "EE8CCBDD-8127-6661-D402-000000000300",
```
