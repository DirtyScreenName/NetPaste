interface ChromeSidePanelApi {
  setPanelBehavior(options: { openPanelOnActionClick: boolean }): Promise<void>;
}

declare const chrome:
  | {
      sidePanel?: ChromeSidePanelApi;
    }
  | undefined;

async function configureSidePanel(): Promise<void> {
  if (typeof chrome === 'undefined' || !chrome.sidePanel) {
    return;
  }

  try {
    await chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });
  } catch {
    // The side panel remains available from the extension menu if this API is unavailable.
  }
}

void configureSidePanel();
