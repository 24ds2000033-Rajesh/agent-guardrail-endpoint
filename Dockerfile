FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

# Create test directories and set permissions as root
RUN mkdir -p /srv/agent-redteam/outside-3fccc998 \
    /srv/agent-redteam/sandbox-d0ba812122/notes \
    /srv/agent-redteam/sandbox-d0ba812122/encoded

EXPOSE 3000

CMD ["npm", "start"]
