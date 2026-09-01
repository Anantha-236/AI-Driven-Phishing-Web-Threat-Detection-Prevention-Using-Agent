import { SCHEMA_V3_VERSION } from "../schema/version";
import {
  PageArtifact,
  FormArtifact,
  InputArtifact,
  ScriptArtifact,
  RequestArtifact,
  NavigationArtifact,
  EvidenceRelationship,
  EvidenceCollection,
  DataTypeCategory
} from "../schema/types";
import { classifyInputDataTypes, InputStructuralMetadata } from "./data-type-classifier";

let idCounter = 0;
function generateId(prefix: string): string {
  idCounter++;
  return `${prefix}-${Date.now().toString(36)}-${idCounter}`;
}

export class ArtifactManager {
  private page: PageArtifact | null = null;
  private forms: Map<string, FormArtifact> = new Map();
  private inputs: Map<string, InputArtifact> = new Map();
  private scripts: Map<string, ScriptArtifact> = new Map();
  private requests: Map<string, RequestArtifact> = new Map();
  private navigations: Map<string, NavigationArtifact> = new Map();
  private relationships: EvidenceRelationship[] = [];

  public createPageArtifact(url: string, title: string): PageArtifact {
    let domain = "";
    let isHTTPS = false;
    try {
      const parsed = new URL(url);
      domain = parsed.hostname;
      isHTTPS = parsed.protocol === "https:";
    } catch {
      domain = url;
    }

    const page: PageArtifact = {
      id: generateId("page"),
      type: "page",
      timestamp: Date.now(),
      url,
      domain,
      title,
      formIds: [],
      scriptCount: 0,
      isHTTPS
    };
    this.page = page;
    return page;
  }

  public createFormArtifact(
    action: string,
    method: string,
    inputElementsData: Array<{
      inputType: string;
      name: string;
      idAttribute: string;
      autocomplete: string;
      placeholder?: string;
      ariaLabel?: string;
      accept?: string;
      capture?: string;
      isRequired?: boolean;
    }>,
    target?: string
  ): FormArtifact {
    if (!this.page) {
      throw new Error("PageArtifact must be created before FormArtifact");
    }

    const formId = generateId("form");
    let isCrossDomain = false;
    try {
      if (action) {
        const actionUrl = new URL(action, this.page.url);
        isCrossDomain = actionUrl.hostname !== this.page.domain;
      }
    } catch {
      isCrossDomain = false;
    }

    const inputIds: string[] = [];
    let hasPassword = false;
    let hasOtp = false;
    const autocompleteAttrs: string[] = [];
    const formDataTypes = new Set<DataTypeCategory>();

    for (const inputData of inputElementsData) {
      const structMeta: InputStructuralMetadata = {
        inputType: inputData.inputType,
        name: inputData.name,
        idAttribute: inputData.idAttribute,
        autocomplete: inputData.autocomplete,
        placeholder: inputData.placeholder,
        ariaLabel: inputData.ariaLabel,
        accept: inputData.accept,
        capture: inputData.capture,
        isRequired: inputData.isRequired
      };

      const detectedTypes = classifyInputDataTypes(structMeta);
      detectedTypes.forEach((t) => formDataTypes.add(t));

      const isPass = detectedTypes.includes("PASSWORD") || inputData.inputType.toLowerCase() === "password";
      const isOtpField = detectedTypes.includes("OTP") || inputData.inputType.toLowerCase() === "one-time-code";

      if (isPass) hasPassword = true;
      if (isOtpField) hasOtp = true;
      if (inputData.autocomplete) autocompleteAttrs.push(inputData.autocomplete);

      const inputArtifact: InputArtifact = {
        id: generateId("input"),
        type: "input",
        formId,
        pageId: this.page.id,
        timestamp: Date.now(),
        inputType: inputData.inputType,
        name: inputData.name,
        idAttribute: inputData.idAttribute,
        autocomplete: inputData.autocomplete,
        isPassword: isPass,
        isOtp: isOtpField,
        detectedDataTypes: detectedTypes,
        isRequired: inputData.isRequired
      };

      this.inputs.set(inputArtifact.id, inputArtifact);
      inputIds.push(inputArtifact.id);

      this.relationships.push({
        sourceId: formId,
        targetId: inputArtifact.id,
        relation: "contains"
      });
    }

    const formArtifact: FormArtifact = {
      id: formId,
      type: "form",
      pageId: this.page.id,
      timestamp: Date.now(),
      action,
      isCrossDomain,
      method: method.toUpperCase() || "GET",
      inputIds,
      hasPasswordField: hasPassword,
      hasOtpField: hasOtp,
      autocompleteAttributes: autocompleteAttrs,
      detectedDataTypes: Array.from(formDataTypes),
      target
    };

    this.forms.set(formId, formArtifact);
    this.page.formIds.push(formId);

    this.relationships.push({
      sourceId: this.page.id,
      targetId: formId,
      relation: "contains"
    });

    return formArtifact;
  }

  public createScriptArtifact(src?: string, isInline: boolean = false): ScriptArtifact {
    if (!this.page) {
      throw new Error("PageArtifact must be created before ScriptArtifact");
    }

    let isCrossDomain = false;
    if (src) {
      try {
        const scriptUrl = new URL(src, this.page.url);
        isCrossDomain = scriptUrl.hostname !== this.page.domain;
      } catch {
        isCrossDomain = false;
      }
    }

    const script: ScriptArtifact = {
      id: generateId("script"),
      type: "script",
      pageId: this.page.id,
      timestamp: Date.now(),
      src,
      isInline,
      isCrossDomain
    };

    this.scripts.set(script.id, script);
    this.page.scriptCount++;

    this.relationships.push({
      sourceId: this.page.id,
      targetId: script.id,
      relation: "contains"
    });

    return script;
  }

  public createNavigationArtifact(targetUrl: string, referrer: string): NavigationArtifact {
    if (!this.page) {
      throw new Error("PageArtifact must be created before NavigationArtifact");
    }

    const nav: NavigationArtifact = {
      id: generateId("nav"),
      type: "navigation",
      timestamp: Date.now(),
      targetUrl,
      referrer,
      pageId: this.page.id
    };

    this.navigations.set(nav.id, nav);

    this.relationships.push({
      sourceId: nav.id,
      targetId: this.page.id,
      relation: "navigates_to"
    });

    return nav;
  }

  public exportCollection(): EvidenceCollection {
    if (!this.page) {
      throw new Error("No page artifact initialized");
    }

    const allCategories = new Set<DataTypeCategory>();
    this.inputs.forEach((input) => {
      if (input.detectedDataTypes) {
        input.detectedDataTypes.forEach((cat) => allCategories.add(cat));
      }
    });

    return {
      schemaVersion: SCHEMA_V3_VERSION,
      collectionId: generateId("coll"),
      timestamp: Date.now(),
      page: { ...this.page },
      forms: Array.from(this.forms.values()),
      inputs: Array.from(this.inputs.values()),
      scripts: Array.from(this.scripts.values()),
      requests: Array.from(this.requests.values()),
      relationships: [...this.relationships],
      requestedDataTypes: Array.from(allCategories)
    };
  }
}

