export const API_BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

/**
 * Wrapper for fetch that handles Render free tier cold starts.
 * If the request takes longer than 3 seconds without returning, it triggers the onColdStart callback.
 */
export async function fetchWithColdStart(endpoint, options = {}, onColdStart = () => {}) {
  const url = `${API_BASE_URL}${endpoint}`;
  
  let isColdStart = false;
  const timeoutId = setTimeout(() => {
    isColdStart = true;
    onColdStart(true); // Signal that server is warming up
  }, 3000);

  try {
    const response = await fetch(url, options);
    clearTimeout(timeoutId);
    if (isColdStart) onColdStart(false); // Clear warning

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.detail || `Server error: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    clearTimeout(timeoutId);
    if (isColdStart) onColdStart(false);
    throw error;
  }
}
