# 🛡️ AI Shield

**Personal AI Security Agent** — Protects everyday users from AI-powered cyber attacks like phishing and audio deepfakes.

*Stateless Web App Edition*

## Overview

AI Shield has been refactored into a full-stack, stateless web application designed to be deployed for free on Vercel (frontend) and Render (backend). It features:
1. **AI Phishing Detector**: Uses a locally cached Hugging Face ML model (`roberta-base-openai-detector`) via FastAPI to detect AI-generated text.
2. **Deepfake Voice Scanner**: Scans audio files (up to 50MB) for synthetic voice patterns using `librosa` and Isolation Forest.
3. **Stateless Privacy**: Zero database footprint. No emails or audio files are saved. Session dashboard stats reset automatically on server sleep.
4. **Browser Extension**: A Chrome extension that integrates directly into Gmail, actively warning users of suspicious incoming emails.

## 🚀 Deploying to the Cloud (Free Tier)

### 1. Deploy the Backend (Render)
The backend is a FastAPI python server that does the heavy lifting.
1. Create a free account on [Render](https://render.com/).
2. Connect your GitHub repository.
3. Click **New > Blueprint** and select this repository. Render will automatically use the included `render.yaml` file to deploy the backend.
4. Wait for the deploy to finish and copy your Render URL (e.g., `https://ai-shield-backend.onrender.com`).

*(Note: The first request after 15 minutes of inactivity may take ~30 seconds as the free-tier server spins up. The frontend and extension gracefully handle this "Cold Start".)*

### 2. Deploy the Frontend (Vercel)
The frontend is a Vite + React application.
1. Create a free account on [Vercel](https://vercel.com/).
2. Click **Add New Project** and import this repository.
3. Set the **Framework Preset** to `Vite`.
4. Set the **Root Directory** to `frontend`.
5. Under Environment Variables, add:
   - `VITE_API_URL`: Your Render backend URL (e.g., `https://ai-shield-backend.onrender.com`)
6. Click **Deploy**.

## 🧩 Installing the Browser Extension

1. Download or clone this repository to your computer.
2. Open Chrome and navigate to `chrome://extensions`.
3. Enable **Developer mode** in the top right corner.
4. Click **Load unpacked** and select the `browser_extension/` folder from this repo.
5. Click the AI Shield icon in your browser toolbar, then click the **Settings (gear)** icon.
6. Enter your backend URL (either your local `http://localhost:8000` or your Render URL).

### 🔒 Security Note for Developers
> The backend CORS configuration is currently locked down to the Vercel frontend and the Chrome extension. 
> **Important**: Before publishing your extension to the Chrome Web Store, edit `api_server.py` and replace `"chrome-extension://YOUR_EXTENSION_ID_HERE"` with the actual extension ID assigned by Google to prevent arbitrary extensions from calling your API.

## 💻 Local Development

If you want to run the project locally on your machine:

### Backend
```bash
# Install dependencies
pip install -r requirements.txt

# Start the FastAPI server
uvicorn api_server:app --reload
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

## 🔒 Data Privacy

AI Shield is designed with your privacy in mind:
- **No Persistent Storage**: All text and audio scanned by the backend are processed entirely in memory and are **never** saved to a database or disk.
- **Immediate Deletion**: Audio files are immediately deleted from temporary storage after the scan completes.
- **No Tracking**: We do not log your email contents, audio contents, or IP addresses.

## 🛠️ Troubleshooting

**Render OOM (Out Of Memory) Errors:**
If the backend crashes frequently with OOM errors on the free tier, it means the ML model is exceeding the 512MB RAM limit. To fix this:
1. Open `render.yaml`.
2. Change the `startCommand` to: `uvicorn api_server:app --host 0.0.0.0 --port $PORT --workers 1 --timeout-keep-alive 5`.
3. Commit and push the changes. Render will redeploy with a single worker and faster connection cleanup.

## Tech Stack
- **Backend**: FastAPI, Transformers (PyTorch), Librosa, scikit-learn
- **Frontend**: React, Vite, React Router, Vanilla CSS
- **Extension**: Chrome Manifest V3, Vanilla JS
- **Hosting**: Render (Web Service), Vercel (Static SPA)
