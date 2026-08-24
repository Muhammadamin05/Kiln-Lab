const jwt = require("jsonwebtoken");

const JWT_SECRET = process.env.JWT_SECRET || "kiln-lab-dev-secret-change-me";

function signToken(user) {
  return jwt.sign(
    { userId: user.id, role: user.role, clinicId: user.clinic_id, name: user.name, isSenior: !!user.is_senior },
    JWT_SECRET,
    { expiresIn: "30d" }
  );
}

function requireAuth(role) {
  return (req, res, next) => {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: "not authenticated" });

    try {
      const payload = jwt.verify(token, JWT_SECRET);
      if (role && payload.role !== role) {
        return res.status(403).json({ error: "forbidden" });
      }
      req.user = payload;
      next();
    } catch (err) {
      return res.status(401).json({ error: "invalid or expired token" });
    }
  };
}

module.exports = { signToken, requireAuth, JWT_SECRET };
