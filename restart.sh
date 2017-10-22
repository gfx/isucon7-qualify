#!/bin/bash
set -e
cd /home/isucon/isubata/webapp
git pull
sudo /usr/sbin/nginx -t
sudo service nginx reload
sudo service isubata.nodejs.service
