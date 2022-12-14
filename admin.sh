#!/bin/bash
docker run --rm -v /var/posmbot:/data -it posmbot_server python3 admin.py $@
