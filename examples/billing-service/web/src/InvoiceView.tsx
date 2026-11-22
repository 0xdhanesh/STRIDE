export function InvoiceView({ invoice }) {
  // Renders the customer-supplied memo as HTML
  return <div dangerouslySetInnerHTML={{ __html: invoice.memo }} />;
}
