from app import app, db, User

with app.app_context():
    user = User.query.filter_by(email="jonathanjerabe@gmail.com").first()
    if user:
        print(f"Before update:")
        print(f"  stripe_customer_id: {user.stripe_customer_id}")
        print(f"  stripe_subscription_id: {user.stripe_subscription_id}")
        print(f"  subscription_status: {user.subscription_status}")
        
        # Set default values for subscription fields
        user.subscription_status = 'active'  # Since has_paid is True
        user.subscription_start_date = user.payment_date if user.payment_date else None
        user.subscription_end_date = None
        
        db.session.commit()
        print("✅ User updated with subscription fields")
        
        # Verify the update
        updated_user = User.query.filter_by(email="jonathanjerabe@gmail.com").first()
        print(f"After update:")
        print(f"  stripe_customer_id: {updated_user.stripe_customer_id}")
        print(f"  stripe_subscription_id: {updated_user.stripe_subscription_id}")
        print(f"  subscription_status: {updated_user.subscription_status}")
    else:
        print("User not found!")