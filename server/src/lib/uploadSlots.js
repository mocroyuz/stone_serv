// Limite de concurrence des uploads vidéo / photos (anti OOM).
// Chaque upload bufferise jusqu'à 100 Mo en RAM. Le slot est acquis AVANT
// de lire le corps de la requête.

import { MAX_VIDEO_UPLOADS } from "../config/index.js";
import { HttpError } from "./utils.js";

const MAX_VIDEO_QUEUE = 10;
const VIDEO_QUEUE_TIMEOUT_MS = 60_000;

let activeVideoUploads = 0;
const videoUploadWaiters = [];

const busyError = () =>
  new HttpError(
    503,
    "Server is busy processing uploads. Try again shortly.",
    "UPLOAD_QUEUE_FULL"
  );

export function acquireVideoSlot() {
  if (activeVideoUploads < MAX_VIDEO_UPLOADS) {
    activeVideoUploads++;
    return Promise.resolve();
  }

  if (videoUploadWaiters.length >= MAX_VIDEO_QUEUE) {
    return Promise.reject(busyError());
  }

  return new Promise((resolve, reject) => {
    const waiter = {
      resolve: () => {
        clearTimeout(waiter.timer);
        resolve();
      },
    };

    waiter.timer = setTimeout(() => {
      const index = videoUploadWaiters.indexOf(waiter);
      if (index !== -1) videoUploadWaiters.splice(index, 1);
      reject(busyError());
    }, VIDEO_QUEUE_TIMEOUT_MS);

    videoUploadWaiters.push(waiter);
  });
}

export function releaseVideoSlot() {
  const next = videoUploadWaiters.shift();

  if (next) {
    // Le slot est transféré au suivant : le compteur ne bouge pas.
    next.resolve();
  } else {
    activeVideoUploads = Math.max(0, activeVideoUploads - 1);
  }
}
