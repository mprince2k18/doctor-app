<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class AppController extends Controller
{
    // all_doctors
    public function all_doctors()
    {
        $doctors = \App\Models\User::where('role', 'doctor')->get();
        return response()->json($doctors);
    }

    //doctors_profile
    public function doctors_profile($user_id)
    {
        $doctor = \App\Models\User::where('id', $user_id)->first();
        return response()->json($doctor);
    }

    //doctors_profile_update
    public function doctors_profile_update($user_id, Request $request)
    {
        $doctor = \App\Models\User::where('id', $user_id)->first();
        $doctor->speciality = $request->speciality;
        $doctor->qualification = $request->qualification;
        $doctor->experience = $request->experience;
        $doctor->address = $request->address;
        $doctor->phone = $request->phone;
        $doctor->save();
        return response()->json($doctor);
    }

    //all_patient
    public function all_patient()
    {
        $patients = \App\Models\User::where('role', 'patient')->get();
        return response()->json($patients);
    }

    //make_appointment
    public function make_appointment(Request $request)
    {
        $appointment = new \App\Models\Appointment;
        $appointment->patient_id = $request->patient_id;
        $appointment->doctor_id = $request->doctor_id;
        $appointment->date = $request->date;
        $appointment->time = $request->time;
        $appointment->status = 0;
        $appointment->save();
        return response()->json($appointment);
    }

    // accept_appointment
    public function accept_appointment($appointment_id)
    {
        $appointment = \App\Models\Appointment::where('id', $appointment_id)->first();
        $appointment->status = 1;
        $appointment->save();
        return response()->json($appointment);
    }

    // appointment_list
    public function appointment_list()
    {
        $appointments = \App\Models\Appointment::all();
        return response()->json($appointments);
    }

    // appointment_list_doctor
    public function appointment_list_doctor($user_id)
    {
        $appointments = \App\Models\Appointment::where('doctor_id', $user_id)->get();
        return response()->json($appointments);
    }

    // appointment_list_patient
    public function appointment_list_patient($user_id)
    {
        $appointments = \App\Models\Appointment::where('patient_id', $user_id)->get();
        return response()->json($appointments);
    }

    // appointment_list_patient_doctor
    public function appointment_list_patient_doctor($user_id)
    {
        $appointments = \App\Models\Appointment::where('patient_id', $user_id)->orWhere('doctor_id', $user_id)->get();
        return response()->json($appointments);
    }

    // give_prescription
    public function give_prescription(Request $request)
    {
        $prescription = new \App\Models\Prescription;
        $prescription->appointment_id = $request->appointment_id;
        $prescription->patient_id = $request->patient_id;
        $prescription->doctor_id = $request->doctor_id;
        $prescription->medicine = $request->medicine;
        $prescription->dosage = $request->dosage;
        $prescription->instruction = $request->instruction;
        $prescription->save();
        return response()->json($prescription);
    }

    //prescription_list
    public function prescription_list()
    {
        $prescriptions = \App\Models\Prescription::all();
        return response()->json($prescriptions);
    }

    //ENDS
}
