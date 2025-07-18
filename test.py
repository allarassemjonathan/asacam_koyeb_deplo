from app import app, db
from sqlalchemy import text

with app.app_context():
    try:
        db.session.execute(text('ALTER TABLE users ADD COLUMN num_cameras INTEGER DEFAULT 1 NOT NULL'))
        db.session.commit()
        print("✅ Added num_cameras column successfully")
    except Exception as e:
        print(f"num_cameras column: {e}")