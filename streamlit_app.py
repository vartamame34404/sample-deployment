import streamlit as st
import patient_crypto as crypto
import admin_auth as auth

st.set_page_config(page_title="DNA-Encrypted Patient Records", layout="centered")
st.title("🧬 Patient Identity Encryption using DNA")

menu = st.sidebar.selectbox("Choose Action", ["Encrypt and Store", "Decrypt and View", "Register Admin" ,"Delete Patient Record"])

# Reset admin auth state when changing to "Decrypt and View"
if "last_menu" not in st.session_state:
    st.session_state.last_menu = menu
elif st.session_state.last_menu != menu:
    if menu == "Decrypt and View":
        st.session_state.otp_verified = False
    st.session_state.last_menu = menu


# ---------- ENCRYPT AND STORE ---------- #
if menu == "Encrypt and Store":
    st.subheader("🔐 Encrypt and Store Patient Data")
    
    patient_id = st.text_input("Patient ID")
    full_name = st.text_input("Full Name")
    email = st.text_input("Email")
    contact = st.text_input("Contact Number")
    dob = st.date_input("Date of Birth")
    gender = st.radio("Gender", ["Male", "Female", "Other"])
    address = st.text_area("Address")
    dna_sequence = st.text_area("Enter DNA Sequence")

    if st.button("Encrypt and Save"):
        if all([patient_id, full_name, email, contact, dob, gender, address, dna_sequence]):
            try:
                success = crypto.store_patient_data(
                    patient_id, full_name, email, contact, dob.strftime("%Y-%m-%d"),
                    gender, address, dna_sequence
                )
                if success:
                    st.success("✅ Patient data encrypted and stored successfully.")
                else:
                    st.error("❌ Database error occurred during insertion.")
            except ValueError as ve:
                st.error(str(ve))
            except Exception as e:
                st.error("❌ Unexpected error: " + str(e))
        else:
            st.warning("Please fill all fields.")

# ---------- DECRYPT AND VIEW ---------- #
elif menu == "Decrypt and View":
    st.subheader("🔓 Decrypt Patient Data")

    # Step: OTP verification (no face auth in cloud version)
    if not st.session_state.get("otp_verified"):
        st.info("📧 Admin OTP Verification Required")
        if auth.authenticate_admin():
            st.session_state.otp_verified = True
            st.success("✅ Admin Authentication Complete")
            st.rerun()

    # Step: View decrypted data
    if st.session_state.get("otp_verified"):
        patient_id = st.text_input("Enter Patient ID")
        if patient_id:
            try:
                data = crypto.retrieve_and_decrypt(patient_id)
                if data:
                    st.success("🔓 Decrypted Patient Data:")
                    st.write("**Full Name:**", data['full_name'])
                    st.write("**Email:**", data['email'])
                    st.write("**Contact:**", data['contact_number'])
                    st.write("**DOB:**", data['dob'])
                    st.write("**Gender:**", data['gender'])
                    st.write("**Address:**", data['address'])
                    st.write("**Created At:**", data['created_at'])
                    st.write("**Updated At:**", data['updated_at'])
                else:
                    st.error("❌ Patient ID not found or decryption failed.")
            except Exception as e:
                st.error(f"❌ Decryption error: {str(e)}")
        else:
            st.warning("Please enter a valid Patient ID.")

# ---------- REGISTER ADMIN ---------- #
elif menu == "Register Admin":
    st.subheader("🛡️ Admin Registration")
    auth.register_new_admin()

elif menu == "Delete Patient Record":
    st.subheader("🗑️ Delete Patient Data")

    # Step: OTP verification (no face auth in cloud version)
    if not st.session_state.get("otp_verified"):
        st.info("📧 Admin OTP Verification Required")
        if auth.authenticate_admin():
            st.session_state.otp_verified = True
            st.success("✅ Admin Authentication Complete")
            st.rerun()

    # Step: Delete record
    if st.session_state.get("otp_verified"):
        patient_id = st.text_input("Enter Patient ID to Delete")
        if st.button("Delete Record"):
            if not patient_id:
                st.warning("Please enter a valid Patient ID.")
            else:
                success, message = crypto.delete_patient_record(patient_id)
                if success:
                    st.success(message)
                else:
                    st.error(message)
