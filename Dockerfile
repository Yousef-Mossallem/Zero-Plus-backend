FROM node:22-alpine              # نقطة البداية: Node (Prisma 7 محتاج 20.19 أو أحدث)
WORKDIR /app                     # الشغل جوه فولدر /app
COPY package*.json ./            # انسخ ملفات المكتبات الأول (عشان الكاش)
RUN npm ci                       # ثبّت المكتبات بالظبط من package-lock
COPY . .                         # انسخ باقي الكود
RUN npx prisma generate          # ولّد Prisma Client جوه الصندوق
RUN npm run build                # ابني الكود
EXPOSE 4000
CMD ["sh", "-c", "npx prisma migrate deploy && npm start"]