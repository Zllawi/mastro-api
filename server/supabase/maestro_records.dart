enum MaestroUserRole {
  customer,
  craftsman,
  admin;

  static MaestroUserRole fromWire(String value) {
    return MaestroUserRole.values.firstWhere((role) => role.name == value);
  }
}

enum MaestroAccountStatus {
  pending,
  active,
  suspended,
  deleted;

  static MaestroAccountStatus fromWire(String value) {
    return MaestroAccountStatus.values.firstWhere(
      (status) => status.name == value,
    );
  }
}

enum MaestroRequestStatus {
  draft,
  submitted,
  offersReceived('offers_received'),
  accepted,
  onTheWay('on_the_way'),
  started,
  completed,
  cancelled,
  disputed;

  const MaestroRequestStatus([String? wireName]) : wireName = wireName ?? '';

  final String wireName;

  String get wire => wireName.isEmpty ? name : wireName;

  static MaestroRequestStatus fromWire(String value) {
    return MaestroRequestStatus.values.firstWhere(
      (status) => status.wire == value,
    );
  }
}

enum MaestroOfferStatus {
  submitted,
  accepted,
  rejected,
  withdrawn,
  expired;

  static MaestroOfferStatus fromWire(String value) {
    return MaestroOfferStatus.values.firstWhere(
      (status) => status.name == value,
    );
  }
}

class MaestroProfile {
  const MaestroProfile({
    required this.id,
    required this.role,
    required this.status,
    required this.phone,
    this.fullName,
    this.city,
    this.phoneVerifiedAt,
    this.createdAt,
  });

  factory MaestroProfile.fromMap(Map<String, dynamic> row) {
    return MaestroProfile(
      id: row['id'].toString(),
      role: MaestroUserRole.fromWire(row['role'].toString()),
      status: MaestroAccountStatus.fromWire(row['status'].toString()),
      phone: row['phone'].toString(),
      fullName: row['full_name']?.toString(),
      city: row['city']?.toString(),
      phoneVerifiedAt: _date(row['phone_verified_at']),
      createdAt: _date(row['created_at']),
    );
  }

  final String id;
  final MaestroUserRole role;
  final MaestroAccountStatus status;
  final String phone;
  final String? fullName;
  final String? city;
  final DateTime? phoneVerifiedAt;
  final DateTime? createdAt;
}

class CreateProfileInput {
  const CreateProfileInput({
    required this.role,
    required this.phone,
    this.fullName,
    this.city = 'Benghazi',
  });

  final MaestroUserRole role;
  final String phone;
  final String? fullName;
  final String city;
}

class UpsertCustomerAddressInput {
  const UpsertCustomerAddressInput({
    required this.customerId,
    required this.label,
    required this.city,
    required this.area,
    required this.address,
    this.landmark,
  });

  final String customerId;
  final String label;
  final String city;
  final String area;
  final String address;
  final String? landmark;
}

class UpsertCraftsmanProfileInput {
  const UpsertCraftsmanProfileInput({
    required this.profileId,
    required this.profession,
    required this.yearsExperience,
    required this.serviceAreas,
    required this.identityType,
    required this.identityNumber,
    this.bio,
  });

  final String profileId;
  final String profession;
  final int yearsExperience;
  final List<String> serviceAreas;
  final String identityType;
  final String identityNumber;
  final String? bio;
}

class CraftsmanVerificationDocumentInput {
  const CraftsmanVerificationDocumentInput({
    required this.craftsmanId,
    required this.documentType,
    required this.storageBucket,
    required this.storagePath,
    this.contentType,
  });

  final String craftsmanId;
  final String documentType;
  final String storageBucket;
  final String storagePath;
  final String? contentType;
}

class MaestroServiceRequest {
  const MaestroServiceRequest({
    required this.id,
    required this.publicCode,
    required this.customerId,
    required this.categoryId,
    required this.status,
    required this.title,
    required this.description,
    required this.urgency,
    this.area,
    this.addressText,
    this.scheduledFor,
    this.createdAt,
  });

  factory MaestroServiceRequest.fromMap(Map<String, dynamic> row) {
    return MaestroServiceRequest(
      id: row['id'].toString(),
      publicCode: row['public_code'].toString(),
      customerId: row['customer_id'].toString(),
      categoryId: row['category_id'].toString(),
      status: MaestroRequestStatus.fromWire(row['status'].toString()),
      title: row['title'].toString(),
      description: row['description'].toString(),
      urgency: row['urgency'] == true,
      area: row['area']?.toString(),
      addressText: row['address_text']?.toString(),
      scheduledFor: _date(row['scheduled_for']),
      createdAt: _date(row['created_at']),
    );
  }

  final String id;
  final String publicCode;
  final String customerId;
  final String categoryId;
  final MaestroRequestStatus status;
  final String title;
  final String description;
  final bool urgency;
  final String? area;
  final String? addressText;
  final DateTime? scheduledFor;
  final DateTime? createdAt;
}

class CreateServiceRequestInput {
  const CreateServiceRequestInput({
    required this.customerId,
    required this.categoryId,
    required this.title,
    required this.description,
    this.urgency = false,
    this.area,
    this.addressText,
    this.scheduledFor,
  });

  final String customerId;
  final String categoryId;
  final String title;
  final String description;
  final bool urgency;
  final String? area;
  final String? addressText;
  final DateTime? scheduledFor;
}

class MaestroOffer {
  const MaestroOffer({
    required this.id,
    required this.requestId,
    required this.craftsmanId,
    required this.status,
    required this.totalAmount,
    required this.currency,
    this.arrivalWindow,
    this.estimatedDuration,
    this.warrantyText,
    this.note,
    this.createdAt,
  });

  factory MaestroOffer.fromMap(Map<String, dynamic> row) {
    return MaestroOffer(
      id: row['id'].toString(),
      requestId: row['request_id'].toString(),
      craftsmanId: row['craftsman_id'].toString(),
      status: MaestroOfferStatus.fromWire(row['status'].toString()),
      totalAmount: _num(row['total_amount']),
      currency: row['currency'].toString(),
      arrivalWindow: row['arrival_window']?.toString(),
      estimatedDuration: row['estimated_duration']?.toString(),
      warrantyText: row['warranty_text']?.toString(),
      note: row['note']?.toString(),
      createdAt: _date(row['created_at']),
    );
  }

  final String id;
  final String requestId;
  final String craftsmanId;
  final MaestroOfferStatus status;
  final num totalAmount;
  final String currency;
  final String? arrivalWindow;
  final String? estimatedDuration;
  final String? warrantyText;
  final String? note;
  final DateTime? createdAt;
}

class SubmitOfferInput {
  const SubmitOfferInput({
    required this.requestId,
    required this.craftsmanId,
    required this.totalAmount,
    this.arrivalWindow,
    this.estimatedDuration,
    this.warrantyText,
    this.note,
  });

  final String requestId;
  final String craftsmanId;
  final num totalAmount;
  final String? arrivalWindow;
  final String? estimatedDuration;
  final String? warrantyText;
  final String? note;
}

DateTime? _date(Object? value) {
  if (value == null) {
    return null;
  }
  if (value is DateTime) {
    return value;
  }
  return DateTime.tryParse(value.toString());
}

num _num(Object? value) {
  if (value is num) {
    return value;
  }
  return num.parse(value.toString());
}
