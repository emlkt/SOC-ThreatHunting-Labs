# Andromeda Bot - UNC4210 Lab

[Andromeda Bot - UNC4210 Lab](https://cyberdefenders.org/blueteam-ctf-challenges/andromeda-bot-unc4210/) (лаборатория хоть и маленькая, но мне показалась достаточно интересной)

**Использовала инструменты:** MemProcFS, EvtxECmd, Timeline Explorer и VirusTotal.

**Сценарий:**
Команда DFIR компании SecuTech расследует инцидент: несколько рабочих станций скомпрометированы, есть подозрение на распространение через USB-устройства. Предоставлен образ памяти (memory.dmp) одной из машин.

---

#### Вопрос 1. Какой серийный номер у USB-устройства, подключённого к системе?

**Ответ:** `7095411056659025437&0`

Монтирование:
```powershell
.\memprocfs.exe -device '..\..\..\Artifacts\memory.dmp' -forensic 3
```
После монтирования перешла в `M:\py\reg\usb\usb_storage.txt` и нашла серийный номер в этом файле.

<img width="500" height="200" alt="серийный номер" src="https://github.com/user-attachments/assets/8d4ec39d-9507-4627-ac4a-fdd709122ed2" />

---

#### Вопрос 2. Когда было последнее зафиксированное подключение этого USB-устройства?

**Ответ:** `2024-10-04 13:48`
В том же файле `usb_storage.txt` нашла временную метку. Для доп. проверки открыла соседний файл `usb_devices.txt` и там подтвердилась та же дата и время.

---

#### Вопрос 3. После того как PowerShell-команды отключили защиту Windows Defender, какой исполняемый файл был запущен? Укажи полный путь.

**Ответ:** `E:\hidden\Trusted Installer.exe`

1. Экспортировала логи PowerShell через EvtxECmd:
```cmd
EvtxECmd.exe -d "M:\forensic\files\ROOT\Windows\System32\winevt\Logs" --csv C:\Users\Administrator\Desktop\logs --csvf 123.csv
```
2. Открыла csv в visual studio и нашла команду:
```powershell
powershell.exe -ExecutionPolicy Bypass -Command Set-MpPreference -DisableRealtimeMonitoring $true; ... ; Start-Process 'E:\hidden\Trusted Installer.exe'
```
(сразу искала по DisableRealtimeMonitoring)

3. `+` подтвердила в Timeline Explorer, отфильтровав события по времени и пользователю.

<img width="550" height="400" alt="визуал студио лог" src="https://github.com/user-attachments/assets/a378be7e-ed4c-4ce8-98dc-a6b51ad110a1" /> <img width="550" height="450" alt="файл после отключения" src="https://github.com/user-attachments/assets/7a673a8f-f045-433a-aa3c-e66782c578f0" />

---

#### Вопрос 4. Согласно отчётам разведки угроз, какой URL использует бот для загрузки файла управления (C&C)?

**Ответ:** `http://anam0rph.su/in.php`

В Timeline Explorer нашла хеш Trusted Installer.exe (9535A9BB1AE8F620D7CBD7D9F5C20336B0FD2C78D1A7D892D76E4652DD8B2BE7). Загрузила его в VirusTotal. Перешла на вкладку Behavior и нашла сетевые запросы и домен `anam0rph.su` через MITRE.

<img width="500" height="200" alt="hash" src="https://github.com/user-attachments/assets/fb8fa20e-b306-4ccc-a8ef-cd5d465fd56d" /> <img width="500" height="300" alt="c2" src="https://github.com/user-attachments/assets/e6dd3c6f-8eca-48c3-b554-4a3e0e269d57" />

---

#### Вопрос 5. Какой MD5 хеш у сброшенного исполняемого файла?

**Ответ:** `7FE00CC4EA8429629AC0AC610DB51993`

В Timeline Explorer нашла связь:
`"C:\Users\Tomy\AppData\Local\Temp\Sahofivizu.exe" + "E:\hidden\Trusted Installer.exe"`
и рядом нашла хеш.

---

#### Вопрос 6. Укажи полный путь к первой DLL, сброшенной образцом малвари.

**Ответ:** `C:\Users\Tomy\AppData\Local\Temp\Gozekeneka.dll`

В Timeline Explorer отфильтровала события по родительскому процессу `Trusted Installer.exe`. Нашла несколько созданных `.dll`-файлов. Первая по времени - `Gozekeneka.dll` в папке `Temp`.

<img width="500" height="300" alt="dll" src="https://github.com/user-attachments/assets/10cc16dc-017f-4458-8d26-ba74ce3a625d" />

---

#### Вопрос 7. Какая APT группа реактивировала эту малварь для использования в своих кампаниях?

**Ответ:** `Turla`

Немного погуглила и нашла статью:
[Turla и бот Andromeda](https://xakep.ru/2023/01/10/turla-andromeda/)
