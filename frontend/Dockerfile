FROM nginx:1.27-alpine

# наш конфиг заменит дефолтный
COPY nginx.conf /etc/nginx/conf.d/default.conf

# статику копируем в стандартную директорию nginx
COPY . /usr/share/nginx/html

EXPOSE 80
