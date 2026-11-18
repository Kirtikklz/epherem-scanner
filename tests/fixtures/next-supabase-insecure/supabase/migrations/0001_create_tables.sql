-- Fixture migration. Intentionally missing ENABLE ROW LEVEL SECURITY.
CREATE TABLE profiles (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL,
  is_admin boolean DEFAULT false
);

CREATE TABLE users (
  id uuid PRIMARY KEY,
  email text NOT NULL
);
