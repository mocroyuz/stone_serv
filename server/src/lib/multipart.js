// Parsing multipart (avatar, vidéo, photos).

import busboy from "busboy";
import { HttpError } from "./utils.js";

export function parseMultipart(req, { fileField, maxSize }) {
  return new Promise((resolve, reject) => {
    let bb;

    try {
      bb = busboy({
        headers: req.headers,
        limits: {
          fileSize: maxSize,
          files: 1,
          fields: 20,
          fieldSize: 16 * 1024,
          parts: 30,
        },
      });
    } catch {
      reject(new HttpError(400, "Invalid multipart request"));
      return;
    }

    const fields = {};
    const chunks = [];
    let fileFound = false;
    let tooLarge = false;
    let mimeType = "";
    let fileName = "";
    let settled = false;

    const settle = (fn, arg) => {
      if (settled) return;
      settled = true;
      fn(arg);
    };

    bb.on("file", (fieldname, file, info) => {
      if (fieldname !== fileField || fileFound) {
        file.resume();
        return;
      }

      fileFound = true;
      mimeType = info?.mimeType || "";
      fileName = info?.filename || "";

      file.on("data", (chunk) => chunks.push(chunk));
      file.on("limit", () => {
        tooLarge = true;
      });
    });

    bb.on("field", (name, value) => {
      fields[name] = value;
    });

    bb.on("filesLimit", () =>
      settle(reject, new HttpError(400, "Too many files"))
    );
    bb.on("partsLimit", () =>
      settle(reject, new HttpError(400, "Too many fields"))
    );

    bb.on("close", () => {
      if (tooLarge) {
        settle(reject, new HttpError(400, "File too large", "FILE_TOO_LARGE"));
        return;
      }

      if (!fileFound) {
        settle(reject, new HttpError(400, "No file", "NO_FILE"));
        return;
      }

      settle(resolve, {
        buffer: Buffer.concat(chunks),
        mimeType,
        fileName,
        fields,
      });
    });

    bb.on("error", () =>
      settle(reject, new HttpError(400, "Could not read the uploaded file."))
    );

    // Un client qui coupe la connexion ne doit jamais laisser la
    // promesse (et donc un slot d'upload) pendante.
    req.on("close", () => {
      if (!req.complete) {
        settle(reject, new HttpError(400, "Upload aborted"));
      }
    });
    req.on("error", () =>
      settle(reject, new HttpError(400, "Upload aborted"))
    );

    req.pipe(bb);
  });
}

// Variante multi-fichiers (carrousel de photos).
export function parseMultipartFiles(req, { fileField, maxFiles, maxFileSize }) {
  return new Promise((resolve, reject) => {
    let bb;

    try {
      bb = busboy({
        headers: req.headers,
        limits: {
          fileSize: maxFileSize,
          files: maxFiles,
          fields: 30,
          fieldSize: 16 * 1024,
          parts: maxFiles + 40,
        },
      });
    } catch {
      reject(new HttpError(400, "Invalid multipart request"));
      return;
    }

    const fields = {};
    const files = [];
    let tooLarge = false;
    let tooMany = false;
    let settled = false;

    const settle = (fn, arg) => {
      if (settled) return;
      settled = true;
      fn(arg);
    };

    bb.on("file", (fieldname, file, info) => {
      if (fieldname !== fileField) {
        file.resume();
        return;
      }

      const chunks = [];

      file.on("data", (chunk) => chunks.push(chunk));
      file.on("limit", () => {
        tooLarge = true;
      });
      file.on("end", () => {
        files.push({
          buffer: Buffer.concat(chunks),
          mimeType: info?.mimeType || "",
          fileName: info?.filename || "",
        });
      });
    });

    bb.on("field", (name, value) => {
      fields[name] = value;
    });

    bb.on("filesLimit", () => {
      tooMany = true;
    });

    bb.on("partsLimit", () =>
      settle(reject, new HttpError(400, "Too many fields"))
    );

    bb.on("close", () => {
      if (tooLarge) {
        settle(reject, new HttpError(400, "File too large", "FILE_TOO_LARGE"));
        return;
      }

      if (tooMany) {
        settle(reject, new HttpError(400, "Too many files", "TOO_MANY_FILES"));
        return;
      }

      if (files.length === 0) {
        settle(reject, new HttpError(400, "No file", "NO_FILE"));
        return;
      }

      settle(resolve, { files, fields });
    });

    bb.on("error", () =>
      settle(reject, new HttpError(400, "Could not read the uploaded files."))
    );

    req.on("close", () => {
      if (!req.complete) {
        settle(reject, new HttpError(400, "Upload aborted"));
      }
    });
    req.on("error", () =>
      settle(reject, new HttpError(400, "Upload aborted"))
    );

    req.pipe(bb);
  });
}
