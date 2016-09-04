# Automatically add/update/remove containers from hosts-file

docker-etchosts is a script that monitors dockers event stream, and
adds/updates/removes containers to your (/etc/)hosts-file on the fly.
The script is based on [dockermon by CyberInt](http://pythonwise.blogspot.de/2015/07/dockermon-docker-process-monitor.html).

## Usage

Started without further parameters the script will connect to `/var/run/docker.sock` and modify `hosts` in the current working directory.
It will also process all currently running containers.

To connect to a remote docker node or swarm cluster use `--socket-url`, e.g.

    python docker-etchosts.py --socker-url='tcp:///localhost:2335'

To specify the full path to your hosts file you would like modified pass `--hosts-file=/etc/hosts`.
To skip processing running containers on script startup pass `--skip-running`.

## Running in a container

The script runs fine dockerized, the supplied Dockerfile creates a image of about 80 MB size,
running consumes about 15 MB RAM.

### build

    docker build -t dockerhosts:pre .

### run

    docker run -v /etc/hosts:/hosts -v /var/run/docker.sock:/var/run/docker.sock --privileged dockerhosts:pre

### run and use tcp socket

    docker run -v /etc/hosts:/hosts --privileged dockerhosts:pre --socket-url=tcp:///localhost:2335

### docker-compose

...or instead of the above, just do:

    docker-compose up -d

:)
