FROM node:22-alpine AS builder
WORKDIR /app
# 与宿主机 .npmrc 一致：默认源在国内网络不可达，npm ci 层缓存失效时需要镜像源
RUN npm config set registry https://registry.npmmirror.com
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npx vite build

# W3: 钉 minor, latest 漂移不可复现
FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
