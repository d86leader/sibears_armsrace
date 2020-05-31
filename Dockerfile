FROM python:3.6

RUN pip3 install aiomysql==0.0.20 pyopenssl==17.5.0
ADD verifier.py /usr/bin/verifier.py

CMD ["/usr/bin/env", "python3", "/usr/bin/verifier.py"]
