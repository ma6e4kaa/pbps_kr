all: PICOFoxweb

clean:
	@rm -rf *.o
	@rm -rf PICOFoxweb

PICOFoxweb: main.o httpd.o auth.o
	gcc -o PICOFoxweb $^ -lpam -lpam_misc -lssl -lcrypto

main.o: main.c httpd.h
	gcc -c -o main.o main.c

httpd.o: httpd.c httpd.h
	gcc -c -o httpd.o httpd.c

auth.o: auth.c auth.h
	gcc -c -o auth.o auth.c

install: PICOFoxweb
	install -o root -g root -m 0755 PICOFoxweb /usr/local/sbin/                       
	install -o root -g root -m 0644 picofoxweb.service /etc/systemd/system/           
	systemctl daemon-reload                                                           
	systemctl restart picofoxweb.service
	mkdir -p /var/www/foxweb
	cp -r webroot -t /var/www/foxweb/
	chown -R root:root /var/www/foxweb
	touch /var/log/foxweb.log
	chown root:root /var/log/foxweb.log
	install -o root -g root -m 0644 picofoxweb.pam /etc/pam.d/picofoxweb

uninstall:
	systemctl stop picofoxweb
	rm -f /var/log/foxweb.log
	rm -rf /var/www/foxweb
	rm -f /usr/local/sbin/PICOFoxweb
	rm -f /etc/systemd/system/picofoxweb.service
	rm -f /etc/pam.d/picofoxweb
	systemctl daemon-reload
