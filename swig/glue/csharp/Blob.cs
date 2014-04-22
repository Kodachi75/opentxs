/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 3.0.0
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */

namespace OpenTransactions.OTAPI {

public class Blob : Storable {
  private global::System.Runtime.InteropServices.HandleRef swigCPtr;

  internal Blob(global::System.IntPtr cPtr, bool cMemoryOwn) : base(otapiPINVOKE.Blob_SWIGUpcast(cPtr), cMemoryOwn) {
    swigCPtr = new global::System.Runtime.InteropServices.HandleRef(this, cPtr);
  }

  internal static global::System.Runtime.InteropServices.HandleRef getCPtr(Blob obj) {
    return (obj == null) ? new global::System.Runtime.InteropServices.HandleRef(null, global::System.IntPtr.Zero) : obj.swigCPtr;
  }

  ~Blob() {
    Dispose();
  }

  public override void Dispose() {
    lock(this) {
      if (swigCPtr.Handle != global::System.IntPtr.Zero) {
        if (swigCMemOwn) {
          swigCMemOwn = false;
          otapiPINVOKE.delete_Blob(swigCPtr);
        }
        swigCPtr = new global::System.Runtime.InteropServices.HandleRef(null, global::System.IntPtr.Zero);
      }
      global::System.GC.SuppressFinalize(this);
      base.Dispose();
    }
  }

  public VectorUnsignedChar m_memBuffer {
    set {
      otapiPINVOKE.Blob_m_memBuffer_set(swigCPtr, VectorUnsignedChar.getCPtr(value));
    } 
    get {
      global::System.IntPtr cPtr = otapiPINVOKE.Blob_m_memBuffer_get(swigCPtr);
      VectorUnsignedChar ret = (cPtr == global::System.IntPtr.Zero) ? null : new VectorUnsignedChar(cPtr, false);
      return ret;
    } 
  }

  public new static Blob ot_dynamic_cast(Storable pObject) {
    global::System.IntPtr cPtr = otapiPINVOKE.Blob_ot_dynamic_cast(Storable.getCPtr(pObject));
    Blob ret = (cPtr == global::System.IntPtr.Zero) ? null : new Blob(cPtr, false);
    return ret;
  }

}

}
