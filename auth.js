const jwt = require("jsonwebtoken");

const JWT_SECRET = process.env.JWT_SECRET || "kiln-lab-dev-secret-change-me";

// payload.role is 'lab' | 'clinic' | 'technician'.
// payload.labId identifies the tenant for every role.
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "30d" });
}

function requireAuth(role) {
  return (req, res, next) => {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: "not authenticated" });

    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (role && decoded.role !== role) {
        return res.status(403).json({ error: "forbidden" });
      }
      req.user = decoded;
      next();
    } catch (err) {
      return res.status(401).json({ error: "invalid or expired token" });
    }
  };
}

module.exports = { signToken, requireAuth, JWT_SECRET };
