# Kerberoasted Lab

[Kerberoasted Lab](https://cyberdefenders.org/blueteam-ctf-challenges/kerberoasted/) 

**Категория:** Threat Hunting  
**Тактики:** Credential Access, Discovery  
**Инструменты:** Splunk / ELK (winlogbeat, Sysmon)
 
---
 
## Сценарий:
 
Гипотеза для расследования: растёт число Kerberoasting-атак в отрасли, может ли организация быть потенциальной целью? Расследование начинается с анализа логов с контроллера домена, на котором включён аудит Kerberos Service Ticket Operations и установлен Sysmon для расширенного мониторинга.
 
---
 
## MITRE ATT&CK маппинг
 
| Тактика | Техника | ID | Наблюдение |
|---|---|---|---|
| Credential Access | Kerberoasting | T1558.003 | TGS-REQ с etype 0x17 (RC4-HMAC) от johndoe к SQLService |
| Discovery | Account Discovery | T1087 | Последовательные TGS запросы к разным SPN за секунды |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 | Вход через RDP после взлома сервисной учётки |
| Persistence | Windows Management Instrumentation | T1546.003 | WMI Event Subscription (consumer updater) |
| Defense Evasion | Modify Registry | T1112 | Включение RDP через fDenyTSConnections |
 
---
 
## Вопросы и ответы 
 
### Вопрос 1: Какой тип шифрования используется в сети?
 
**Ответ:** `RC4-HMAC`
 
Искала через событие `4769` - это запрос TGS (Ticket Granting Service). При Kerberoasting смотреть нужно именно на него, так как атакующий запрашивает сервисный билет, который потом ломается оффлайн, а так же на поле `Ticket Encryption Type`.
 
```
index="kerberoasted" AND "event.code"=4769
```
 
В логах `TicketEncryptionType: 0x17` - это и есть RC4-HMAC, старый алгоритм шифрования. Современные домены должны использовать AES-256 (0x12), но RC4 часто оставляют включённым для совместимости. А RC4-хэш ломается hashcat значительно быстрее AES.
 
<img width="400" height="400" alt="1 вопрос" src="https://github.com/user-attachments/assets/c42ebc20-b562-40ce-8c88-cee96a560867" />

---
 
### Вопрос 2: Какой пользователь последовательно запросил TGS для двух разных сервисов за короткое время?
 
**Ответ:** `johndoe`
 
Искала по таблице с пользователями, сервисами и временными метками:
 
```
index="kerberoasted" "event.code"=4769
| table winlog.event_data.TargetUserName, winlog.event_data.ServiceName, _time
```
 
`johndoe@CYBERCACTUS.LOCAL` в течение одной секунды запросил билеты сразу для двух разных машин:
 
```
johndoe@CYBERCACTUS.LOCAL | DC01$         | 2023-10-15 17:56:03.352
johndoe@CYBERCACTUS.LOCAL | MARKETINGPC$  | 2023-10-15 17:56:03.197
```
 
Два разных SPN за ~150 мс похоже на инструмент типа rubeus, который перечисляет все доступные SPN и сразу достает билеты.
 
<img width="1000" height="80" alt="2 вопрос" src="https://github.com/user-attachments/assets/80bc5a3a-9c4a-43b7-be40-4016ab84af33" />

---
 
### Вопрос 3: Какая сервисная учётка была скомпрометирована?
 
**Ответ:** `SQLService`
 
Смотрела дальше по активности `johndoe`, какие ещё сервисы он запрашивал:
 
```
index="kerberoasted" "event.code"=4769 "winlog.event_data.TargetUserName"="johndoe@CYBERCACTUS.LOCAL"
| table winlog.event_data.ServiceName, _time
```
 
Увидела запрос к `SQLService` в 19:30, а уже в 19:44 пошли запросы к `DC01$` и `krbtgt`. Выглядит как цепочка: взломал пароль SQLService оффлайн, залогинился под ней, и дальше уже с её правами двинулся к контроллеру домена. А `krbtgt` в конце знак, что атакующий пытался получить максимальные привилегии.
 
 <img width="1000" height="60" alt="3 вопрос" src="https://github.com/user-attachments/assets/f7bfe811-7bed-4f91-a123-fc31170ce1b9" />

---
 
### Вопрос 4: Какой IP-адрес у машины, с которой начиналась атака?
 
**Ответ:** `10.0.0.154`
 
Посмотрела поле `winlog.event_data.IpAddress` в событиях от `johndoe`.
 
<img width="900" height="130" alt="4 вопрос" src="https://github.com/user-attachments/assets/3bb82429-1d2a-49a6-ad5f-ecbd1f6d3c01" />

---
 
### Вопрос 5: Какой сервис был установлен на контроллере домена после компрометации?
 
**Ответ:** `iOOEDsXjWeGRAyGl`
 
Event id `7045` - это установка новой службы в Windows. Искала на DC:
 
```
index="kerberoasted" event.code=7045 host="DC01"
```
 
Нашла всего два события, одно из которых это служба с рандомным именем `iOOEDsXjWeGRAyGl`. Случайные имена служб это типичный паттерн: инструменты типа smbexec или psexec создают временные службы для выполнения команд, и называют их рандомно чтобы не светиться. В данном случае, судя по контексту, через неё выполнялись команды на DC уже от имени скомпрометированной учётки.
 
<img width="1000" height="100" alt="5вопрос" src="https://github.com/user-attachments/assets/31c4e9b8-ef51-47d6-a1c3-4deaa9a9cbed" />

---
 
### Вопрос 6: Какой ключ реестра изменил атакующий чтобы включить RDP?
 
**Ответ:** `HKLM\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections`
 
Искала через Sysmon Event ID `13` - событие изменения значения реестра + фильтровала по `reg.exe` на DC:
 
```
index="kerberoasted" host="DC01" *reg.exe* "event.code"=13
```
 
<img width="900" height="380" alt="6вопрос" src="https://github.com/user-attachments/assets/bf56c6d0-e1ec-498c-a1a5-fc85686c1ee6" />

---
 
### Вопрос 7: Когда произошёл первый RDP-вход?
 
**Ответ:** `2023-10-16 07:50`
 
Event ID `4624` +  LogonType `10` - это именно RemoteInteractive, то есть вход через RDP (в отличие от, например, сетевого входа с типом 3)
 
```
index="kerberoasted" host="DC01" "event.code"=4624 "winlog.event_data.LogonType"=10
```
 
<img width="450" height="300" alt="7вопрос" src="https://github.com/user-attachments/assets/7f974556-eea5-4f10-9bce-72b5992bb28a" />
 
---
 
### Вопрос 8: Как называется WMI Event Consumer, обеспечивающий постоянство?
 
**Ответ:** `updater`
 
WMI это один из способов закрепления в системе: создаётся фильтр (условие-триггер), consumer (что сделать при срабатывании) и binding (связь между ними). Sysmon пишет это в Event id 19-21.
 
```
index="kerberoasted" host="DC01" "winlog.event_id"=20 "winlog.event_data.EventType"=WmiConsumerEvent
```
 
<img width="450" height="300" alt="8вопрос" src="https://github.com/user-attachments/assets/e74a4e76-997e-48fb-b401-7ad050fe253e" />

---
 
### Вопрос 9: На какой класс нацелен фильтр WMI Event Subscription?
 
**Ответ:** `win32_ntlogevent`
 
Искала по Sysmon Event id `19` - это регистрация WMI Event Filter:
 
```
index="kerberoasted" host="DC01" "winlog.event_id"=19
```

В поле `Query` оказался полный запрос:
 
```sql
SELECT * FROM __InstanceCreationEvent WITHIN 60
WHERE TargetInstance ISA 'Win32_NTLogEvent'
AND TargetInstance.EventCode = '4625'
AND TargetInstance.Message LIKE '%johndoe%'
```
 
Атакующий настроил триггер: если кто-то начнёт пытаться войти под `johndoe` и падать с ошибками, то consumer `updater` выполнит какое-то действие. Скорее всего атакующий хочет знать если кто-то обнаружил учётку и начал её использовать.
 
<img width="800" height="166" alt="9вопрос" src="https://github.com/user-attachments/assets/4cebad38-d10e-4875-98a6-37cf19fe9318" />
 
---
 
