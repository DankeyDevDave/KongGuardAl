/**
 * Kong Guard AI - Visual Effects for Demo Recording
 * Provides click indicators, highlights, and visual feedback
 */

// Brand colors from Kong Guard AI
const BRAND_COLORS = {
  bg: '#0f1113',
  surface: '#171a1f',
  line: '#2a3037',
  txt: '#c8ccd3',
  silver: '#e6e8ec',
  steel: '#aeb4bd',
  accent: '#4a9eff'
};

/**
 * Initialize visual effects system
 */
function initializeVisualEffects() {
  // Inject CSS for visual effects
  injectVisualEffectsCSS();
  
  // Create click ripple container
  createRippleContainer();
  
  // Create progress indicator
  createProgressIndicator();
  
  console.log('Kong Guard AI Visual Effects initialized');
}

/**
 * Inject CSS styles for visual effects
 */
function injectVisualEffectsCSS() {
  const style = document.createElement('style');
  style.textContent = `
    /* Click Ripple Effect */
    .kg-click-ripple {
      position: fixed;
      border-radius: 50%;
      background: ${BRAND_COLORS.accent};
      pointer-events: none;
      z-index: 999999;
      opacity: 0.6;
      animation: kg-ripple-expand 0.8s ease-out forwards;
    }
    
    @keyframes kg-ripple-expand {
      0% {
        transform: scale(0);
        opacity: 0.8;
      }
      50% {
        opacity: 0.6;
      }
      100% {
        transform: scale(20);
        opacity: 0;
      }
    }
    
    /* Element Highlight Effect */
    .kg-highlight {
      outline: 3px solid ${BRAND_COLORS.steel} !important;
      outline-offset: 4px !important;
      box-shadow: 0 0 30px rgba(174, 180, 189, 0.8) !important;
      border-radius: 8px !important;
      animation: kg-pulse 1.5s ease-in-out infinite;
      position: relative;
      z-index: 9998;
    }
    
    @keyframes kg-pulse {
      0%, 100% {
        box-shadow: 0 0 30px rgba(174, 180, 189, 0.8);
        outline-offset: 4px;
      }
      50% {
        box-shadow: 0 0 50px rgba(174, 180, 189, 1);
        outline-offset: 6px;
      }
    }
    
    /* Progress Indicator */
    .kg-progress-indicator {
      position: fixed;
      bottom: 20px;
      right: 20px;
      background: linear-gradient(180deg, ${BRAND_COLORS.surface}, ${BRAND_COLORS.bg});
      border: 1px solid ${BRAND_COLORS.line};
      border-radius: 8px;
      padding: 16px 24px;
      z-index: 999998;
      font-family: 'Rajdhani', 'Inter', system-ui, sans-serif;
      color: ${BRAND_COLORS.txt};
      backdrop-filter: blur(10px);
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.6);
      min-width: 300px;
    }
    
    .kg-progress-header {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 8px;
      color: ${BRAND_COLORS.steel};
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }
    
    .kg-progress-title {
      color: ${BRAND_COLORS.silver};
      font-size: 16px;
      font-weight: 600;
      margin-bottom: 4px;
    }
    
    .kg-progress-narration {
      color: ${BRAND_COLORS.txt};
      font-size: 13px;
      line-height: 1.4;
      margin-bottom: 12px;
      max-height: 60px;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    
    .kg-progress-bar {
      width: 100%;
      height: 4px;
      background: ${BRAND_COLORS.line};
      border-radius: 2px;
      overflow: hidden;
      margin-bottom: 8px;
    }
    
    .kg-progress-fill {
      height: 100%;
      background: linear-gradient(90deg, ${BRAND_COLORS.accent}, ${BRAND_COLORS.steel});
      transition: width 0.3s ease;
      border-radius: 2px;
    }
    
    .kg-progress-time {
      display: flex;
      justify-content: space-between;
      font-size: 11px;
      color: ${BRAND_COLORS.steel};
      font-weight: 500;
    }
    
    /* Scene Badge */
    .kg-scene-badge {
      position: fixed;
      top: 20px;
      right: 20px;
      background: ${BRAND_COLORS.surface};
      border: 1px solid ${BRAND_COLORS.line};
      border-radius: 6px;
      padding: 8px 16px;
      z-index: 999998;
      font-family: 'Rajdhani', 'Inter', system-ui, sans-serif;
      color: ${BRAND_COLORS.silver};
      font-size: 14px;
      font-weight: 600;
      backdrop-filter: blur(10px);
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4);
    }
    
    .kg-scene-number {
      color: ${BRAND_COLORS.accent};
      margin-right: 4px;
    }
    
    /* Hover Indicator */
    .kg-hover-indicator {
      position: fixed;
      pointer-events: none;
      z-index: 999997;
      width: 24px;
      height: 24px;
      border: 2px solid ${BRAND_COLORS.accent};
      border-radius: 50%;
      background: rgba(74, 158, 255, 0.2);
      transform: translate(-50%, -50%);
      animation: kg-hover-pulse 1s ease-in-out infinite;
    }
    
    @keyframes kg-hover-pulse {
      0%, 100% {
        transform: translate(-50%, -50%) scale(1);
        opacity: 1;
      }
      50% {
        transform: translate(-50%, -50%) scale(1.3);
        opacity: 0.7;
      }
    }
    
    /* Screenshot Flash */
    .kg-screenshot-flash {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: white;
      pointer-events: none;
      z-index: 999999;
      opacity: 0;
      animation: kg-flash 0.3s ease-out;
    }
    
    @keyframes kg-flash {
      0% {
        opacity: 0;
      }
      50% {
        opacity: 0.5;
      }
      100% {
        opacity: 0;
      }
    }
  `;
  document.head.appendChild(style);
}

/**
 * Create ripple container for click effects
 */
function createRippleContainer() {
  const container = document.createElement('div');
  container.id = 'kg-ripple-container';
  document.body.appendChild(container);
}

/**
 * Show click ripple effect at coordinates
 */
function showClickRipple(x, y) {
  const ripple = document.createElement('div');
  ripple.className = 'kg-click-ripple';
  ripple.style.left = `${x}px`;
  ripple.style.top = `${y}px`;
  ripple.style.width = '40px';
  ripple.style.height = '40px';
  ripple.style.marginLeft = '-20px';
  ripple.style.marginTop = '-20px';
  
  document.body.appendChild(ripple);
  
  setTimeout(() => {
    ripple.remove();
  }, 800);
}

/**
 * Highlight an element
 */
function highlightElement(selector, duration = 3000) {
  const element = document.querySelector(selector);
  if (!element) {
    console.warn(`Element not found: ${selector}`);
    return;
  }
  
  element.classList.add('kg-highlight');
  
  // Scroll element into view smoothly
  element.scrollIntoView({ behavior: 'smooth', block: 'center' });
  
  if (duration > 0) {
    setTimeout(() => {
      element.classList.remove('kg-highlight');
    }, duration);
  }
}

/**
 * Remove highlight from an element
 */
function removeHighlight(selector) {
  const element = document.querySelector(selector);
  if (element) {
    element.classList.remove('kg-highlight');
  }
}

/**
 * Create progress indicator
 */
function createProgressIndicator() {
  const indicator = document.createElement('div');
  indicator.id = 'kg-progress-indicator';
  indicator.className = 'kg-progress-indicator';
  indicator.innerHTML = `
    <div class="kg-progress-header">
      <span>🎬</span>
      <span>RECORDING IN PROGRESS</span>
    </div>
    <div class="kg-progress-title" id="kg-scene-title">Initializing...</div>
    <div class="kg-progress-narration" id="kg-scene-narration"></div>
    <div class="kg-progress-bar">
      <div class="kg-progress-fill" id="kg-progress-fill" style="width: 0%"></div>
    </div>
    <div class="kg-progress-time">
      <span id="kg-time-current">0:00</span>
      <span id="kg-time-total">0:00</span>
    </div>
  `;
  document.body.appendChild(indicator);
}

/**
 * Create scene badge
 */
function createSceneBadge() {
  const badge = document.createElement('div');
  badge.id = 'kg-scene-badge';
  badge.className = 'kg-scene-badge';
  badge.innerHTML = `<span class="kg-scene-number">Scene 1</span> / 7`;
  document.body.appendChild(badge);
}

/**
 * Update progress indicator
 */
function updateProgress(sceneInfo, progress) {
  const title = document.getElementById('kg-scene-title');
  const narration = document.getElementById('kg-scene-narration');
  const fill = document.getElementById('kg-progress-fill');
  const timeCurrent = document.getElementById('kg-time-current');
  const timeTotal = document.getElementById('kg-time-total');
  
  if (title && sceneInfo) {
    title.textContent = `Scene ${sceneInfo.number}: ${sceneInfo.title}`;
  }
  
  if (narration && sceneInfo) {
    narration.textContent = sceneInfo.narration.substring(0, 150) + '...';
  }
  
  if (fill && typeof progress === 'number') {
    fill.style.width = `${Math.min(100, Math.max(0, progress))}%`;
  }
  
  if (timeCurrent && sceneInfo) {
    const elapsed = sceneInfo.start_time + (sceneInfo.duration * (progress / 100));
    timeCurrent.textContent = formatTime(elapsed);
  }
  
  if (timeTotal) {
    timeTotal.textContent = formatTime(285); // Total demo duration
  }
}

/**
 * Update scene badge
 */
function updateSceneBadge(sceneNumber, totalScenes) {
  const badge = document.getElementById('kg-scene-badge');
  if (badge) {
    badge.innerHTML = `<span class="kg-scene-number">Scene ${sceneNumber}</span> / ${totalScenes}`;
  } else {
    createSceneBadge();
    updateSceneBadge(sceneNumber, totalScenes);
  }
}

/**
 * Show screenshot flash effect
 */
function showScreenshotFlash() {
  const flash = document.createElement('div');
  flash.className = 'kg-screenshot-flash';
  document.body.appendChild(flash);
  
  setTimeout(() => {
    flash.remove();
  }, 300);
}

/**
 * Format time in M:SS format
 */
function formatTime(seconds) {
  const mins = Math.floor(seconds / 60);
  const secs = Math.floor(seconds % 60);
  return `${mins}:${secs.toString().padStart(2, '0')}`;
}

/**
 * Show hover indicator at coordinates
 */
function showHoverIndicator(x, y, duration = 2000) {
  const indicator = document.createElement('div');
  indicator.className = 'kg-hover-indicator';
  indicator.style.left = `${x}px`;
  indicator.style.top = `${y}px`;
  document.body.appendChild(indicator);
  
  setTimeout(() => {
    indicator.remove();
  }, duration);
}

// Export functions for use by Playwright
window.kgVisualEffects = {
  initialize: initializeVisualEffects,
  showClickRipple,
  highlightElement,
  removeHighlight,
  updateProgress,
  updateSceneBadge,
  showScreenshotFlash,
  showHoverIndicator
};

// Auto-initialize if not in test mode
if (typeof window !== 'undefined' && !window.kgTestMode) {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeVisualEffects);
  } else {
    initializeVisualEffects();
  }
}
