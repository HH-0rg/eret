FROM selenium/standalone-chrome:108.0
USER root
RUN apt update
RUN apt install -y python python3-pip
WORKDIR /app
ADD decompile.py .
ADD requirements.txt .
ADD .env .
RUN pip3 install -r requirements.txt
EXPOSE 8000
CMD ["python3", "decompile.py"]

