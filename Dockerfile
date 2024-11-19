FROM python:3


WORKDIR ../panopto-ingestor

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "panopto.py"]