all: PICOFoxweb

clean:
	@rm -rf *.o
	@rm -rf PICOFoxweb

PICOFoxweb: main.o httpd.o
	gcc -o PICOFoxweb $^

main.o: main.c httpd.h
	gcc -c -o main.o main.c

httpd.o: httpd.c httpd.h
	gcc -c -o httpd.o httpd.c

install: PICOFoxweb
	useradd -c "PICOFoxweb user" -r -s /sbin/nologin -d /var/www/foxweb picofoxweb
	install -o root -g root -m 0755 PICOFoxweb /usr/local/sbin/                       
	install -o root -g root -m 0644 picofoxweb.service /etc/systemd/system/           
	systemctl daemon-reload                                                           
	systemctl restart picofoxweb.service
	mkdir -p /var/www/foxweb
	cp -r webroot -t /var/www/foxweb/
	chown -R picofoxweb:picofoxweb /var/www/foxweb
	touch /var/log/foxweb.log
	chown picofoxweb:picofoxweb /var/log/foxweb.log

uninstall:
	systemctl stop picofoxweb
	rm -f /var/log/foxweb.log
	rm -rf /var/www/foxweb
	rm -f /usr/local/sbin/PICOFoxweb
	rm -f /etc/systemd/system/picofoxweb.service
	systemctl daemon-reload
	userdel -f picofoxweb
