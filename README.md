# Курсовая работа

Переработанная редакция pico HTTP-сервера на С, выполненная foxweb: 

[https://github.com/foxweb/pico](https://github.com/foxweb/pico)

Является переработкой примера **03.pico**

## Возможности

- Выполняет обработку GET и POST запросов 
- Заполняет структуру полями запроса для возможности дальнейшей обработки
- Позволяет через предопределенные макросы описывать правила маршрутизации запросов
- Обработка каждого запроса в отдельном процессе
- Многофайловая сборка, позволяет производить изменения в основном файле проекта (main.c), в котором отпределяется функция маршрутизации и производится запуск сервера
- Содержит пример реализации функции маршрутизации, выдает запрашиваемые ресурсы из предопределенного каталога
- Логирует запросы в файл /var/log/foxweb.log
- Логирует ошибки через syslog
- Выполняет Basic аутентификацию пользователей через PAM

## Сборка/запуск

- Сборка и запуск

~~~
sudo make install

