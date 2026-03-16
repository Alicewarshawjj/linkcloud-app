# 🚀 LinkCloud - Deployment Guide

LinkCloud is a link-in-bio platform with analytics, admin dashboard, and beautiful customizable profiles.

## ⚡ Quick Deploy to Railway (5 minutes)

### Step 1: Install Railway CLI (Optional)
```bash
npm install -g @railway/cli
railway login
```

### Step 2: Deploy via GitHub (Recommended)

1. **Push to GitHub:**
```bash
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/YOUR_USERNAME/linkcloud.git
git push -u origin main
```

2. **Deploy on Railway:**
   - Go to [railway.app](https://railway.app)
   - Click "Start a New Project"
   - Select "Deploy from GitHub repo"
   - Choose your repository

3. **Add PostgreSQL Database:**
   - Click "+ New"
   - Select "Database" → "PostgreSQL"
   - Railway will automatically set `DATABASE_URL`

4. **Set Environment Variables:**
   - Go to your service → "Variables"
   - Add these variables:

```env
JWT_SECRET=your-random-secret-key-here
ADMIN_USERNAME=admin
ADMIN_PASSWORD=YourSecurePassword123!
NODE_ENV=production
```

5. **Deploy!** 🎉
   - Railway will automatically build and deploy
   - You'll get a URL like: `https://linkcloud-production.up.railway.app`

### Step 3: Access Your Admin Panel

1. Go to: `https://your-app.up.railway.app/admin.html`
2. Login with your `ADMIN_USERNAME` and `ADMIN_PASSWORD`
3. Start creating profiles!

---

## 🔧 Local Development

```bash
# Install dependencies
npm install

# Create .env file
cp .env.example .env

# Edit .env and set your values
# You'll need a PostgreSQL database running

# Run locally
npm run dev
```

Access locally at: `http://localhost:3000`

---

## 📊 Features

✅ **Profile Pages** - Beautiful, customizable link-in-bio pages
✅ **Analytics** - Track clicks, views, and engagement
✅ **Admin Dashboard** - Easy content management
✅ **PostgreSQL** - Reliable data storage
✅ **JWT Auth** - Secure admin authentication
✅ **Rate Limiting** - DDoS protection
✅ **SEO Optimized** - Meta tags and social sharing

---

## 🔐 Security Notes

- ⚠️ **CHANGE DEFAULT PASSWORDS** before deploying!
- ✅ Uses bcrypt for password hashing (12 rounds)
- ✅ JWT tokens for session management
- ✅ Helmet.js for security headers
- ✅ Rate limiting on all endpoints

---

## 🌐 Alternative Deployment Options

### Vercel (Frontend Only)
```bash
cd public
vercel deploy
```

### Docker
```bash
docker-compose up -d
```

### Hetzner/VPS
```bash
./deploy.sh yourdomain.com your@email.com
```

---

## 📝 Environment Variables Reference

| Variable | Description | Required |
|----------|-------------|----------|
| `DATABASE_URL` | PostgreSQL connection string | ✅ Yes |
| `JWT_SECRET` | Secret key for JWT tokens | ✅ Yes |
| `ADMIN_USERNAME` | Admin login username | ✅ Yes |
| `ADMIN_PASSWORD` | Admin login password | ✅ Yes |
| `NODE_ENV` | Environment (production/development) | ✅ Yes |
| `PORT` | Server port (default: 3000) | ⚠️ Auto-set by Railway |

---

## 🆘 Troubleshooting

**Database connection fails:**
- Ensure `DATABASE_URL` is set in Railway variables
- Check PostgreSQL is running and accessible

**Admin login not working:**
- Check `ADMIN_USERNAME` and `ADMIN_PASSWORD` in variables
- Try resetting the database (will recreate admin user)

**Page not loading:**
- Check Railway logs: `railway logs`
- Ensure `PORT` is not hardcoded (Railway sets it automatically)

---

## 📞 Support

For issues or questions, check the logs:
```bash
railway logs
```

---

Built with ❤️ using Node.js + Express + PostgreSQL
