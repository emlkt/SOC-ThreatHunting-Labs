# RoastToRoot Lab 

[RoastToRoot Lab ](https://cyberdefenders.org/blueteam-ctf-challenges/roasttoroot/)

### Category: Network Forensics

### Инструменты:

- **Wireshark**  -  для анализа сетевого трафика.
- **Hashcat** - для оффлайн-взлома хэшей Kerberos (режимы 18200 и 13100).
- **7zip** - для распаковки найденного архива с инструментами эксфильтрации.
- **PowerShell** - для расчета хэшей файлов (`Get-FileHash`).
- **Notepad++** и VS Code - для просмотра скриптов и конфигов.

Важный момент, который сэкономил мне кучу времени, если бы начала с его сразу: в Wireshark нужно настроить расшифровку трафика.

```
Edit - Preferences - Protocols - NTLMSSP - ввести пароль скомпрометированного пользователя
Edit - Preferences - Protocols - KRB5 - включить "Try to decrypt Kerberos blobs"
```
Без этого пакеты SMB3 зашифрованы, и найти в них имена файлов или команды невозможно. Я поняла это только после нескольких часов поиска альтернативных векторов атаки.

## Сценарий:

После компрометации Linux-сервера злоумышленник переместился глубже в сеть и получил доступ к контроллеру домена. Затем был развернут ransomware в инфраструктуре Wowza Enterprise, что привело к потере бэкапов и простою систем.

---

### Вопрос 1: Какой домен был атакован?

**Ответ:** `wowza.local`
 
(Открыла дамп в Wireshark, применила фильтр `kerberos`. В первом же пакете AS-REQ увидела поле `crealm: WOWZA.LOCAL`. Это название домена wowza.local.)

<img width="800" height="250" alt="вопрос 1" src="https://github.com/user-attachments/assets/554e3a47-00e9-4f3e-916e-c98795f117a3" />

### Вопрос 2: Когда началась рекогносцировка через анонимный/гостевой доступ по SMB?

**Ответ:** `2025-11-25 10:53`

(Применила фильтр `smb2 && (smb2.auth == "Guest" || smb2.auth == "Anonymous")`. Wireshark показал несколько пакетов с аутентификацией без учетных данных. Самый ранний из них (Guest) имел временную метку 10:53)

<img width="1000" height="350" alt="вопрос 2" src="https://github.com/user-attachments/assets/96df2317-2677-4561-b192-bc69611f9177" />

### Вопрос 3: Сколько пользователей было целью AS-REP Roasting и какие у них sAMAccountNames?

**Ответ:** `3, cgarcia`, hthomas`, owright`
  
(as-rep roasting работает у пользователей, у которых отключена пре-аутентификация в kerberos. Поэтому использовала фильтр: `kerberos.msg_type == 11`, из каждого ответа извлекла поле cname-string, это и есть имя пользователя. Получила три имени в порядке появления в трафике)

<img width="1025" height="226" alt="вопрос 3" src="https://github.com/user-attachments/assets/c19a7b81-244d-42f8-8881-0e44b7c4b782" />

### Вопрос 4: Какой пароль был подобран для пользователя после AS-REP Roasting?

**Ответ:** `whatisit`

1. Нашла пакет AS-REP для пользователя cgarcia + тип слабого шифрования etype: 23 (RC4-HMAC-MD5).
2. Скопировала значение cipher из enc-part.
3. Сформировала строку для Hashcat в формате:
   ```
   $krb5asrep$23$cgarcia@WOWZA.LOCAL:<cipher>
   ```
4. Запустила:
   ```
   hashcat -m 18200 hash.txt rockyou.txt
   ```
5. Hashcat быстро нашел пароль: `whatisit`.

<img width="800" height="204" alt="вопрос 4" src="https://github.com/user-attachments/assets/bac15b0d-30cd-4589-9d4c-05debd7d9fcb" />  <img width="450" height="150" alt="это авторизация" src="https://github.com/user-attachments/assets/9b7d1d36-0b98-43ce-9d19-91c9c1775cdc" />

### Вопрос 5: Как назывался текстовый файл, созданный злоумышленником для проверки доступа к шарам?

**Ответ:** `AyUXwZSYKV.txt`

После получения пароля cgarcia ожидала увидеть в трафике smb-пакеты с созданием файла. Применила фильтры:
- `smb2.cmd == 5/6` (CREATE Request)
- `smb2.filename contains ".txt"`
- Поиск по строке .txt через Ctrl+F

В результате пакеты SMB2 есть, но поле `File Name` или не отображается или там указаны названия папок или уже файлы эксфильтрации.

Я потратила достаточное количество времени, проверяя разные варианты. Только потом вспомнила, что после успешной аутентификации Kerberos SMB-трафик может быть зашифрован сессионными ключами. Без этих ключей Wireshark не может распарсить прикладной уровень протокола.

1. В настройках Wireshark добавила пароль whatisit в раздел NTLMSSP.
2. Включила опцию `Try to decrypt Kerberos blobs` в разделе KRB5.
3. После применения настроек пакеты SMB2 поле `File Name` стало читаемым.
4. Нашла пакет Create Request от атакующего к контроллеру домена.
5. В поле File Name увидела: `\Finance\AyUXwZSYKV.txt`.

### Вопрос 6: Как называлась шара, к которой злоумышленник получил доступ вручную?

**Ответ:** `Finance`

(После расшифровки трафика применила фильтр `smb2.tree_connect.request`. В поле Share Name увидела Finance. Это подтвердилось тем, что именно на этой шаре создавался тестовый файл из предыдущего вопроса.)

<img width="600" height="300" alt="вопрос 6" src="https://github.com/user-attachments/assets/07e13ccf-64fd-4b9c-8ed4-15a5bef285d4" />

### Вопрос 7: Какие учетные данные временного администратора были найдены в атрибутах LDAP?

**Ответ:** `tempadmin:admin@9999999!`

1. Фильтр: ldap && frame contains "description"
2. Также помогло, что я уже видела имя tempadmin в предыдущих пакетах. Поиск по строке tempadmin в Packet details привел к нужному пакету searchResEntry.
3. В атрибутах пользователя нашла:
```
Attribute: description
Value: Temp admin account. Username: tempadmin, Password: admin@9999999!
```

<img width="300" height="200" alt="вопрос 7" src="https://github.com/user-attachments/assets/fdd9cabb-537f-44d0-851c-e27021e5ed7e" />

### Вопрос 8: Какой NTSTATUS вернул контроллер домена при попытке аутентификации с учеткой tempadmin?

**Ответ:** `STATUS_ACCOUNT_DISABLED`

1. Фильтр: `smb2 && frame contains "tempadmin"`
2. Нашла пакет Session Setup Response. В поле NTSTATUS увидела код `0xc0000072`, который соответствует STATUS_ACCOUNT_DISABLED.

<img width="400" height="200" alt="вопрос 8" src="https://github.com/user-attachments/assets/db087043-a072-4e46-a651-8b72266cbf24" />

### Вопрос 9: Номер пакета, в котором происходит LDAP Unbind Request (конец сбора данных BloodHound)?

**Ответ:** `5175`
 
1. BloodHound завершает сбор данных отправкой `Unbind Request` (закрытие LDAP-сессии).
2. Ctrl+F - Packet details - String - unbindRequest.
3. Первый найденный пакет с этим сообщением имел номер 5175.

<img width="600" height="200" alt="вопрос 9" src="https://github.com/user-attachments/assets/c09c38c2-39a4-4c9d-b586-00e4f7c12b1e" />

### Вопрос 10: Сколько хэшей сервисных аккаунтов было получено в результате Kerberoasting?

**Ответ:** `5`

(Фильтр: `kerberos.msg_type == 13` (TGS-REP))

<img width="600" height="150" alt="вопрос 10" src="https://github.com/user-attachments/assets/a8579fa7-3eec-46ea-83fd-0410b44c032a" />

### Вопрос 11: Какой сервисный аккаунт был взломан и какой пароль подобран?

**Ответ:** `svc_backup:1180200022358`

1. Нашла пакет TGS-REP для аккаунта svc_backup с etype: 23 
2. Скопировала cipher из ticket → enc-part.
3. Сформировала уже хэш в формате для Kerberoasting:
   ```
   $krb5tgs$23$*svc_backup$WOWZA.LOCAL$wowza.local/svc_backup*$<cipher>
   ```
4. Запустила Hashcat с режимом 13100:
   ```
   hashcat -m 13100 hash.txt rockyou.txt
   ```
5. Пароль найден: `1180200022358`.

<img width="700" height="144" alt="вопрос 11" src="https://github.com/user-attachments/assets/0f926ec6-a5f2-4de5-a942-de9c0f29ac6a" />  <img width="1000" height="275" alt="вопрос11-1" src="https://github.com/user-attachments/assets/2eccef7f-b438-4ef7-af38-8cfe83b16b91" />

### Вопрос 12: Когда была реактивирована учетная запись tempadmin?

**Ответ:** `2025-11-25 11:03`

1. Фильтр: `ldap && frame contains "tempadmin" && ldap.attribute == "userAccountControl"`
2. Нашла пакет Modify Request, в котором изменялся атрибут userAccountControl - он управляет статусом учетки. 

<img width="1000" height="160" alt="вопрос 12" src="https://github.com/user-attachments/assets/0462826f-b54f-4f90-92fb-bd3edcbb227d" />

### Вопрос 13: Как называлась шара, использованная для стадирования файлов перед эксфильтрацией?

**Ответ:** `IT`

(После расшифровки трафика с паролем `admin@9999999!` применила фильтр `smb2.tree_connect.request`. Увидела подключение к шаре IT. В последующих пакетах по этой шаре передавался архив exfil.zip)

<img width="1000" height="195" alt="вопрос 13" src="https://github.com/user-attachments/assets/5082056e-5c08-4821-9151-ee79983c9036" />

### Вопрос 14: SHA-256 хэш архива, загруженного злоумышленником?

**Ответ:** `C9DD39E0E0C11A9F029DD31E9E47614AF4650D1853B55DD3F3D1C504F22B5F38`

**Как искала:**  
1. В трафике нашла пакет с созданием файла exfil.zip на шаре IT.
2. В Wireshark: File → Export Objects → SMB → выбрала exfil.zip → сохранила.
3. В PowerShell рассчитала хэш:
   ```
   Get-FileHash -Path .\exfil.zip -Algorithm SHA256
   ```
<img width="800" height="111" alt="вопрос 14" src="https://github.com/user-attachments/assets/58b09e7f-1906-4abc-a955-0b8aa00eb361" />

### Вопрос 15: Какой инструмент использовался для эксфильтрации и сколько расширений файлов он был настроен собирать?

**Ответ:** `rclone`, `14 расширений`

1. Распаковала exfil.zip через 7zip.
2. Внутри нашла папку rclone-v1.71.2-windows-amd64 с исполняемым файлом  и конфигом.
3. В конфиге увидела список расширений в параметре --include:
   ```
   --include *.doc --include *.xls --include *.pdf ... (всего 14 штук)
   ```

<img width="700" height="400" alt="вопрос 15" src="https://github.com/user-attachments/assets/e08821ac-2c57-4a49-adc0-07ca5a8bd571" />  <img width="600" height="250" alt="ворпос 15-1" src="https://github.com/user-attachments/assets/d9a2f1b5-8f5a-4c5d-95ce-3ec28664f9bd" />

### Вопрос 16: Какой протокол и учетные данные использовались для эксфильтрации?

**Ответ:** `sftp`, `johnattan:johnattan`

(Открыла скрипт exfil.ps1 из архива. В нем нашла команду sftp://johnattan:johnattan@external-server/path)

<img width="600" height="400" alt="вопрос 16" src="https://github.com/user-attachments/assets/c961605b-26fb-4826-905a-1fb30619d1ef" />

### Вопрос 17: Какой инструмент из набора Impacket использовался для получения полуинтерактивной оболочки?

**Ответ:** `smbexec`

(Анализировала пакеты с протоколом SVCCTL (управление службами). В поле CreateServiceW request увидела команду (%COMSPEC% /Q /c echo powershell -ep bypass -command))


### Вопрос 18: Как назывался временный .bat-файл, созданный при выполнении скрипта эксфильтрации?

**Ответ:** `rkhbcfrq.bat`

1. Фильтр: `smb2 && frame contains "exfil.ps1"`
2. Нашла много пакетов с файлом:
```
%SYSTEMROOT%\RKhBcFrQ.bat
```

### Вопрос 19: Какие журналы событий Windows были очищены?

**Ответ:** `system, security, application` (в этом порядке)

1. Сохранила файл clean.ps1 так же как и прошлый архив.
2. Открыла скрипт clean.ps1. В нем нашла последовательность команд:
```powershell
Clear-EventLog -LogName "System"
Clear-EventLog -LogName "Security"
Clear-EventLog -LogName "Application"
```

<img width="800" height="233" alt="вопрос 19" src="https://github.com/user-attachments/assets/63895de5-4b78-485a-bc09-d7d53793aeaf" />

### Вопрос 20: Когда была выполнена последняя команда злоумышленника на контроллере домена?

**Ответ:** `2025-11-25 11:10`

1. Фильтр: `svcctl && frame contains "exfil.ps1"`
2. Нашла последний пакет с выполнением команды через CreateServiceW. Временная метка: 11:10.
