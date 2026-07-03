export type AppSurface = 'web' | 'extension-side-panel';

export interface AppSurfaceOptions {
  surface?: AppSurface;
}

export interface AppSurfaceConfig {
  surface: AppSurface;
  rootClassName: string;
  initialStatus: string;
}

export function resolveAppSurface(
  options: AppSurfaceOptions = {}
): AppSurfaceConfig {
  const surface = options.surface ?? 'web';

  if (surface === 'extension-side-panel') {
    return {
      surface,
      rootClassName: 'extension-surface',
      initialStatus: 'Paste text, clean it locally, review findings, then copy.'
    };
  }

  return {
    surface,
    rootClassName: 'web-surface',
    initialStatus: 'Paste text to begin. All analysis runs locally in this browser.'
  };
}
