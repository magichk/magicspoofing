FROM python:3.8-alpine
RUN mkdir /app
WORKDIR /app
COPY requirements.txt requirements.txt
#COPY src/requirements.txt ./
RUN pip3 install -r requirements.txt
COPY . .
CMD ["python", "magicspoofmail.py"]
EXPOSE 8080

